function int64(low, hi) {
    this.low = (low >>> 0);
    this.hi = (hi >>> 0);

    this.add32inplace = function (val) {
        let new_lo = (((this.low >>> 0) + val) & 0xFFFFFFFF) >>> 0;
        let new_hi = (this.hi >>> 0);

        if (new_lo < this.low) {
            new_hi++;
        }

        this.hi = new_hi;
        this.low = new_lo;
    }

    this.add32 = function (val) {
        let new_lo = (((this.low >>> 0) + val) & 0xFFFFFFFF) >>> 0;
        let new_hi = (this.hi >>> 0);

        if (new_lo < this.low) {
            new_hi++;
        }

        return new int64(new_lo, new_hi);
    }

    this.sub32 = function (val) {
        let new_lo = (((this.low >>> 0) - val) & 0xFFFFFFFF) >>> 0;
        let new_hi = (this.hi >>> 0);

        if (new_lo > (this.low) & 0xFFFFFFFF) {
            new_hi--;
        }

        return new int64(new_lo, new_hi);
    }

    this.sub32inplace = function (val) {
        let new_lo = (((this.low >>> 0) - val) & 0xFFFFFFFF) >>> 0;
        let new_hi = (this.hi >>> 0);

        if (new_lo > (this.low) & 0xFFFFFFFF) {
            new_hi--;
        }

        this.hi = new_hi;
        this.low = new_lo;
    }

    this.and32 = function (val) {
        let new_lo = this.low & val;
        let new_hi = this.hi;
        return new int64(new_lo, new_hi);
    }

    this.and64 = function (vallo, valhi) {
        let new_lo = this.low & vallo;
        let new_hi = this.hi & valhi;
        return new int64(new_lo, new_hi);
    }

    this.toString = function () {
        let lo_str = (this.low >>> 0).toString(16);
        let hi_str = (this.hi >>> 0).toString(16);

        if (this.hi == 0)
            return lo_str;
        else
            lo_str = zeroFill(lo_str, 8)

        return hi_str + lo_str;
    }

    return this;
}

function zeroFill(number, width) {
    width -= number.toString().length;

    if (width > 0) {
        return new Array(width + (/\./.test(number) ? 2 : 1)).join('0') + number;
    }

    return number + ""; // always return a string
}