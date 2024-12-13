import {
  generateKey,
  readPrivateKey,
  reformatKey,
} from 'openpgp/lightweight';
import type {
  GenerateKeyOptions,
  KeyPair,
  PrivateKey,
} from 'openpgp/lightweight';

// WebGPU 使用 WGSL 着色器语言，我们将使用 compute.wgsl 文件
import computeShaderCode from './compute.wgsl?raw';

// SHA-1 测试向量及中间值的函数保持不变

const editPrivateKeyCreationTime = async (privateKey: PrivateKey, created: Date): Promise<KeyPair> => {
  privateKey = await readPrivateKey({ armoredKey: privateKey.armor() });
  await Promise.all(
    [privateKey.keyPacket, ...privateKey.subkeys.map(e => e.keyPacket)]
      .map(e => {
        e.created = created;
        // @ts-ignore
        // computeFingerprintAndKeyID not in d.ts
        // https://github.com/openpgpjs/openpgpjs/blob/a0337780b77093716ba92acb4a70b3bb5ceec87d/src/packet/public_key.js#L200
        return e.computeFingerprintAndKeyID();
      })
  );
  return await reformatKey({
    privateKey,
    userIDs: privateKey.users.map(e => e.userID!),
    date: created,
    format: 'object',
  });
};

const swap32 = (x: number) => (
  ((x & 0xFF) << 24) |
  ((x & 0xFF00) << 8) |
  ((x >> 8) & 0xFF00) |
  ((x >> 24) & 0xFF)
) >>> 0;

export const patternToFilter = (pattern: string) => {
  pattern = pattern.replaceAll(' ', '');
  if (pattern.length != 40) throw new Error('Invalid pattern');
  return [
    ...[0, 8, 16, 24, 32].map((e, i) => {
      const s = pattern.substring(e, e + 8);
      let mask = '';
      let value = '';
      let activated = false;
      for (let i = 0; i < 8; i++) {
        if (s[i].match(/[\da-f]/gi)) {
          mask += 'F';
          value += s[i].toUpperCase();
          activated = true;
        } else {
          mask += '0';
          value += '0';
        }
      }
      return activated ? `(h[${i}] & 0x${mask}u) == 0x${value}u` : '';
    }),
    ...pattern.split('')
      .map((e, i) => e.toUpperCase() === 'X' ? i : null)
      .filter(Boolean)
      .reduce((acc, cur, idx, arr) => {
        const leftIndex = Math.floor(arr[idx - 1]! / 8);
        const rightIndex = Math.floor(cur! / 8);
        const leftDigit = 7 - arr[idx - 1]! % 8;
        const rightDigit = 7 - cur! % 8;
        if (idx) {
          acc.push(`((h[${leftIndex}] ${rightDigit > leftDigit ? '<<' : '>>'} ${Math.abs(rightDigit - leftDigit) * 4}) & 0xF${'0'.repeat(rightDigit)}u) == (h[${rightIndex}] & 0xF${'0'.repeat(rightDigit)}u)`);
          // console.log(arr[idx - 1], cur, acc[acc.length - 1]);
        }
        return acc;
      }, [] as string[]),
  ].filter(Boolean).join(' && ') || 'true';
}

export const createVanityKey = async (
  config: GenerateKeyOptions,
  filter: string,
  thread: number,
  iteration: number,
  progressCallback: (hash: number, time: DOMHighResTimeStamp) => void = () => { },
  checkAbort: (hash: number, time: DOMHighResTimeStamp) => boolean = () => false,
  vanitySubkey: boolean = false,
): Promise<KeyPair | undefined> => {
  const size = Math.round(Math.sqrt(thread));
  let initialized = false;
  let fingerprintDataWithoutHeader = new Uint8Array();
  let fingerprintData = new Uint8Array();
  let hashData = new ArrayBuffer(0);
  let hashDataU8 = new Uint8Array();
  let hashDataU32 = new Uint32Array();
  let hashCount = 0;
  const startTime = performance.now();

  // 初始化 WebGPU
  const adapter = await navigator.gpu.requestAdapter();
  if (!adapter) throw new Error('Failed to get GPU adapter.');
  const device = await adapter.requestDevice();

  // 创建缓冲区和管道
  let computePipeline: GPUComputePipeline;
  let bindGroupLayout: GPUBindGroupLayout;
  let bindGroup: GPUBindGroup;
  let hashDataBuffer: GPUBuffer;
  let resultBuffer: GPUBuffer;
  // let resultArray: Uint32Array;

  return await new Promise<KeyPair | undefined>((resolve, reject) => {
    const run = async () => {
      try {
        const keypair: KeyPair = await generateKey({
          ...config,
          format: 'object',
        });

        // @ts-ignore
        fingerprintDataWithoutHeader = (vanitySubkey ? keypair.publicKey.subkeys[0] : keypair.publicKey).keyPacket.write();

        if (!initialized) {
          // 准备指纹数据
          fingerprintData = new Uint8Array(fingerprintDataWithoutHeader.length + 3);
          fingerprintData[0] = 0x99;
          fingerprintData[1] = (fingerprintDataWithoutHeader.length >> 8) & 0xFF;
          fingerprintData[2] = (fingerprintDataWithoutHeader.length) & 0xFF;
          fingerprintData.set(fingerprintDataWithoutHeader, 3);

          // 准备哈希数据
          const totalLength = Math.ceil((fingerprintData.length + 1 + 8) / 64) * 64;
          hashData = new ArrayBuffer(totalLength);
          hashDataU8 = new Uint8Array(hashData);
          hashDataU32 = new Uint32Array(hashData);

          // SHA-1 填充
          hashDataU8.set(fingerprintData);
          hashDataU8[fingerprintData.length] = 0x80;
          for (let i = 0; i < hashDataU32.length; i++) {
            hashDataU32[i] = swap32(hashDataU32[i]);
          }
          hashDataU32[hashDataU32.length - 1] = fingerprintData.length * 8;

          // 创建 GPU 缓冲区
          hashDataBuffer = device.createBuffer({
            size: hashData.byteLength,
            usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST,
          });
          device.queue.writeBuffer(hashDataBuffer, 0, hashDataU32);

          resultBuffer = device.createBuffer({
            size: 4,
            usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC,
          });

          // resultArray = new Uint32Array(1);

          const shaderCode = computeShaderCode.replace('__FILTER_CONDITION__', filter).replace('__LENGTH__', hashDataU32.length.toString());
          console.log(shaderCode);
          // 创建计算着色器模块
          const shaderModule = device.createShaderModule({
            code: shaderCode,
          });

          // 创建管道
          computePipeline = device.createComputePipeline({
            layout: 'auto',
            compute: {
              module: shaderModule,
              entryPoint: 'main',
            },
          });

          // 创建绑定组
          bindGroupLayout = computePipeline.getBindGroupLayout(0);
          bindGroup = device.createBindGroup({
            layout: bindGroupLayout,
            entries: [
              {
                binding: 0,
                resource: {
                  buffer: hashDataBuffer,
                },
              },
              {
                binding: 1,
                resource: {
                  buffer: resultBuffer,
                },
              },
            ],
          });

          initialized = true;
        } else {
          // 更新哈希数据缓冲区
          device.queue.writeBuffer(hashDataBuffer, 0, hashDataU32);
        }

        // 创建命令编码器
        const commandEncoder = device.createCommandEncoder();

        // 创建计算通道编码器
        const passEncoder = commandEncoder.beginComputePass();
        passEncoder.setPipeline(computePipeline);
        passEncoder.setBindGroup(0, bindGroup);

        // 根据需要调整工作组大小和分派数量
        // const workgroupSize = 256;
        // const numWorkgroups = Math.ceil(size * size * iteration / workgroupSize);
        // passEncoder.dispatchWorkgroups(numWorkgroups);
        passEncoder.dispatchWorkgroups(256, 256, 1);

        passEncoder.end();

        // 复制结果缓冲区以读取数据
        const readBuffer = device.createBuffer({
          size: resultBuffer.size,
          usage: GPUBufferUsage.COPY_DST | GPUBufferUsage.MAP_READ,
        });
        commandEncoder.copyBufferToBuffer(resultBuffer, 0, readBuffer, 0, 4);

        // 提交命令
        const gpuCommands = commandEncoder.finish();
        device.queue.submit([gpuCommands]);

        // 读取结果
        await readBuffer.mapAsync(GPUMapMode.READ);
        const result = new Uint32Array(readBuffer.getMappedRange());
        const foundTimestamp = result[0];
        readBuffer.unmap();

        hashCount += size * size * iteration;
        progressCallback(hashCount, performance.now() - startTime);

        if (foundTimestamp) {
          resolve(await editPrivateKeyCreationTime(keypair.privateKey, new Date(foundTimestamp * 1000)));
        } else if (checkAbort(hashCount, performance.now() - startTime)) {
          resolve(undefined);
        } else {
          setTimeout(run, 0);
        }
      } catch (err) {
        reject(err);
      }
    };
    // 使用 setTimeout 防止阻塞主线程
    setTimeout(run, 0);
  });
};
