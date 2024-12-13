// 定义输入和输出结构
struct HashData {
    data: array<u32>,
};

struct ResultData {
    timestamp: atomic<u32>,
};

@group(0) @binding(0) var<storage> hashData: HashData;
@group(0) @binding(1) var<storage, read_write> resultData: ResultData;

// 定义旋转函数
fn ROTL(x: u32, n: u32) -> u32 {
    return (x << n) | (x >> (32u - n));
}

// 插入过滤器条件和数据长度
const LENGTH: u32 = __LENGTH__;

@compute @workgroup_size(256)
fn main(
    @builtin(global_invocation_id) GlobalInvocationID: vec3<u32>
) {
    let index = GlobalInvocationID.x;
    let iteration = index;

    var data = array<u32, LENGTH>();
    for (var i: u32 = 0u; i < LENGTH; i = i + 1u) {
        data[i] = hashData.data[i];
    }

    let timestamp = data[1];
    data[1] = timestamp - iteration;

    var h = array<u32, 5>(
        0x67452301u,
        0xEFCDAB89u,
        0x98BADCFEu,
        0x10325476u,
        0xC3D2E1F0u
    );

    var w = array<u32, 80>();

    // SHA-1 计算
    for (var chunk: u32 = 0u; chunk < LENGTH / 16u; chunk = chunk + 1u) {
        for (var i: u32 = 0u; i < 16u; i = i + 1u) {
            w[i] = data[chunk * 16u + i];
        }
        for (var i: u32 = 16u; i < 80u; i = i + 1u) {
            w[i] = ROTL(w[i - 3u] ^ w[i - 8u] ^ w[i - 14u] ^ w[i - 16u], 1u);
        }

        var a = h[0];
        var b = h[1];
        var c = h[2];
        var d = h[3];
        var e = h[4];
        var f: u32;
        var k: u32;
        var t: u32;

        for (var i: u32 = 0u; i < 80u; i = i + 1u) {
            if (i < 20u) {
                f = d ^ (b & (c ^ d));
                k = 0x5A827999u;
            } else if (i < 40u) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1u;
            } else if (i < 60u) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDCu;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6u;
            }
            t = ROTL(a, 5u) + f + e + k + w[i];
            e = d;
            d = c;
            c = ROTL(b, 30u);
            b = a;
            a = t;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
    }

    let FILTER_CONDITION: bool = __FILTER_CONDITION__;
    // 应用过滤器条件
    if (FILTER_CONDITION) {
        // 使用原子操作存储结果时间戳
        atomicStore(&resultData.timestamp, data[1]);
    }
}
