const std = @import("../std.zig");
const testing = std.testing;
const math = std.math;

pub const abs = @import("complex/abs.zig").abs;
pub const acosh = @import("complex/acosh.zig").acosh;
pub const acos = @import("complex/acos.zig").acos;
pub const arg = @import("complex/arg.zig").arg;
pub const asinh = @import("complex/asinh.zig").asinh;
pub const asin = @import("complex/asin.zig").asin;
pub const atanh = @import("complex/atanh.zig").atanh;
pub const atan = @import("complex/atan.zig").atan;
pub const conj = @import("complex/conj.zig").conj;
pub const cosh = @import("complex/cosh.zig").cosh;
pub const cos = @import("complex/cos.zig").cos;
pub const exp = @import("complex/exp.zig").exp;
pub const log = @import("complex/log.zig").log;
pub const pow = @import("complex/pow.zig").pow;
pub const proj = @import("complex/proj.zig").proj;
pub const sinh = @import("complex/sinh.zig").sinh;
pub const sin = @import("complex/sin.zig").sin;
pub const sqrt = @import("complex/sqrt.zig").sqrt;
pub const tanh = @import("complex/tanh.zig").tanh;
pub const tan = @import("complex/tan.zig").tan;

pub fn Complex(comptime T: type) type {
    return struct {
        const Self = @This();

        re: T,
        im: T,

        pub fn new(re: T, im: T) Self {
            return Self{
                .re = re,
                .im = im,
            };
        }

        pub fn add(self: Self, other: Self) Self {
            return Self{
                .re = self.re + other.re,
                .im = self.im + other.im,
            };
        }

        pub fn sub(self: Self, other: Self) Self {
            return Self{
                .re = self.re - other.re,
                .im = self.im - other.im,
            };
        }

        pub fn mul(self: Self, other: Self) Self {
            return Self{
                .re = self.re * other.re - self.im * other.im,
                .im = self.im * other.re + self.re * other.im,
            };
        }

        pub fn div(self: Self, other: Self) Self {
            const re_num = self.re * other.re + self.im * other.im;
            const im_num = self.im * other.re - self.re * other.im;
            const den = other.re * other.re + other.im * other.im;

            return Self{
                .re = re_num / den,
                .im = im_num / den,
            };
        }

        pub fn conjugate(self: Self) Self {
            return Self{
                .re = self.re,
                .im = -self.im,
            };
        }

        pub fn reciprocal(self: Self) Self {
            const m = self.re * self.re + self.im * self.im;
            return Self{
                .re = self.re / m,
                .im = -self.im / m,
            };
        }

        pub fn magnitude(self: Self) T {
            return math.sqrt(self.re * self.re + self.im * self.im);
        }
    };
}

const epsilon = 0.0001;

test "complex.add" {
    const a = Complex(f32).new(5, 3);
    const b = Complex(f32).new(2, 7);
    const c = a.add(b);

    testing.expect(c.re == 7 and c.im == 10);
}

test "complex.sub" {
    const a = Complex(f32).new(5, 3);
    const b = Complex(f32).new(2, 7);
    const c = a.sub(b);

    testing.expect(c.re == 3 and c.im == -4);
}

test "complex.mul" {
    const a = Complex(f32).new(5, 3);
    const b = Complex(f32).new(2, 7);
    const c = a.mul(b);

    testing.expect(c.re == -11 and c.im == 41);
}

test "complex.div" {
    const a = Complex(f32).new(5, 3);
    const b = Complex(f32).new(2, 7);
    const c = a.div(b);

    testing.expect(math.approxEq(f32, c.re, f32(31) / 53, epsilon) and
        math.approxEq(f32, c.im, f32(-29) / 53, epsilon));
}

test "complex.conjugate" {
    const a = Complex(f32).new(5, 3);
    const c = a.conjugate();

    testing.expect(c.re == 5 and c.im == -3);
}

test "complex.reciprocal" {
    const a = Complex(f32).new(5, 3);
    const c = a.reciprocal();

    testing.expect(math.approxEq(f32, c.re, f32(5) / 34, epsilon) and
        math.approxEq(f32, c.im, f32(-3) / 34, epsilon));
}

test "complex.magnitude" {
    const a = Complex(f32).new(5, 3);
    const c = a.magnitude();

    testing.expect(math.approxEq(f32, c, 5.83095, epsilon));
}

test "complex.cmath" {
    _ = @import("complex/abs.zig");
    _ = @import("complex/acosh.zig");
    _ = @import("complex/acos.zig");
    _ = @import("complex/arg.zig");
    _ = @import("complex/asinh.zig");
    _ = @import("complex/asin.zig");
    _ = @import("complex/atanh.zig");
    _ = @import("complex/atan.zig");
    _ = @import("complex/conj.zig");
    _ = @import("complex/cosh.zig");
    _ = @import("complex/cos.zig");
    _ = @import("complex/exp.zig");
    _ = @import("complex/log.zig");
    _ = @import("complex/pow.zig");
    _ = @import("complex/proj.zig");
    _ = @import("complex/sinh.zig");
    _ = @import("complex/sin.zig");
    _ = @import("complex/sqrt.zig");
    _ = @import("complex/tanh.zig");
    _ = @import("complex/tan.zig");
}
