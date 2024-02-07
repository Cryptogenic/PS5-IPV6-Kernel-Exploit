/* Copyright (C) 2023 anonymous

This file is part of PSFree.

PSFree is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

PSFree is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

function check_range(x) {
    return (-0x80000000 <= x) && (x <= 0xffffffff);
}

function unhexlify(hexstr) {
    if (hexstr.substring(0, 2) === "0x") {
        hexstr = hexstr.substring(2);
    }
    if (hexstr.length % 2 === 1) {
        hexstr = '0' + hexstr;
    }
    if (hexstr.length % 2 === 1) {
        throw TypeError("Invalid hex string");
    }

    let bytes = new Uint8Array(hexstr.length / 2);
    for (let i = 0; i < hexstr.length; i += 2) {
        let new_i = hexstr.length - 2 - i;
        let substr = hexstr.slice(new_i, new_i + 2);
        bytes[i / 2] = parseInt(substr, 16);
    }

    return bytes;
}

// Decorator for Int instance operations. Takes care
// of converting arguments to Int instances if required.
function operation(f, nargs) {
    return function () {
        if (arguments.length !== nargs)
            throw Error("Not enough arguments for function " + f.name);
        let new_args = [];
        for (let i = 0; i < arguments.length; i++) {
            if (!(arguments[i] instanceof Int)) {
                new_args[i] = new Int(arguments[i]);
            } else {
                new_args[i] = arguments[i];
            }
        }
        return f.apply(this, new_args);
    };
}

class Int {
    constructor(low, high) {
        let buffer = new Uint32Array(2);
        let bytes = new Uint8Array(buffer.buffer);

        if (arguments.length > 2) {
            throw TypeError('Int takes at most 2 args');
        }
        if (arguments.length === 0) {
            throw TypeError('Int takes at min 1 args');
        }
        let is_one = false;
        if (arguments.length === 1) {
            is_one = true;
        }

        if (!is_one) {
            if (typeof (low) !== 'number'
                && typeof (high) !== 'number') {
                throw TypeError('low/high must be numbers');
            }
        }

        if (typeof low === 'number') {
            if (!check_range(low)) {
                throw TypeError('low not a valid value: ' + low);
            }
            if (is_one) {
                high = 0;
                if (low < 0) {
                    high = -1;
                }
            } else {
                if (!check_range(high)) {
                    throw TypeError('high not a valid value: ' + high);
                }
            }
            buffer[0] = low;
            buffer[1] = high;
        } else if (typeof low === 'string') {
            bytes.set(unhexlify(low));
        } else if (typeof low === 'object') {
            if (low instanceof Int) {
                bytes.set(low.bytes);
            } else {
                if (low.length !== 8)
                    throw TypeError("Array must have exactly 8 elements.");
                bytes.set(low);
            }
        } else {
            throw TypeError('Int does not support your object for conversion');
        }

        this.buffer = buffer;
        this.bytes = bytes;

        this.eq = operation(function eq(b) {
            const a = this;
            return a.low() === b.low() && a.high() === b.high();
        }, 1);

        this.neg = operation(function neg() {
            let type = this.constructor;

            let low = ~this.low();
            let high = ~this.high();

            let res = (new Int(low, high)).add(1);

            return new type(res);
        }, 0);

        this.add = operation(function add(b) {
            let type = this.constructor;

            let low = this.low();
            let high = this.high();

            low += b.low();
            let carry = 0;
            if (low > 0xffffffff) {
                carry = 1;
            }
            high += carry + b.high();

            low &= 0xffffffff;
            high &= 0xffffffff;

            return new type(low, high);
        }, 1);

        this.sub = operation(function sub(b) {
            let type = this.constructor;

            b = b.neg();

            let low = this.low();
            let high = this.high();

            low += b.low();
            let carry = 0;
            if (low > 0xffffffff) {
                carry = 1;
            }
            high += carry + b.high();

            low &= 0xffffffff;
            high &= 0xffffffff;

            return new type(low, high);
        }, 1);
    }

    low() {
        return this.buffer[0];
    }

    high() {
        return this.buffer[1];
    }

    toString(is_pretty) {
        if (!is_pretty) {
            let low = this.low().toString(16).padStart(8, '0');
            let high = this.high().toString(16).padStart(8, '0');
            return '0x' + high + low;
        }
        let high = this.high().toString(16).padStart(8, '0');
        high = high.substring(0, 4) + '_' + high.substring(4);

        let low = this.low().toString(16).padStart(8, '0');
        low = low.substring(0, 4) + '_' + low.substring(4);
        return '0x' + high + '_' + low;
    }
}

Int.Zero = new Int(0);
Int.One = new Int(1);
