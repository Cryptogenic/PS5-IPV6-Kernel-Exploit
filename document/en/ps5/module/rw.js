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

// import { Int } from './int64.mjs';

// view.buffer is the underlying ArrayBuffer of a TypedArray, but since we will
// be corrupting the m_vector of our target views later, the ArrayBuffer's
// buffer will not correspond to our fake m_vector anyway.
//
// can't use:
//
// function read32(u8_view, offset) {
//     let res = new Uint32Array(u8_view.buffer, offset, 1);
//     return res[0];
// }
//
// to implement read32, we need to index the view instead:
//
// function read32(u8_view, offset) {
//     let res = 0;
//     for (let i = 0; i < 4; i++) {
//         res += u8_view[offset + i] << i*8;
//     }
//     // << returns a signed integer, >>> converts it to unsigned
//     return res >>> 0;
// }

// for reads less than 8 bytes
function read(u8_view, offset, size) {
    let res = 0;
    for (let i = 0; i < size; i++) {
        res += u8_view[offset + i] << i*8;
    }
    // << returns a signed integer, >>> converts it to unsigned
    return res >>> 0;
}

function read16(u8_view, offset) {
    return read(u8_view, offset, 2);
}

function read32(u8_view, offset) {
    return read(u8_view, offset, 4);
}

function read64(u8_view, offset) {
    let res = [];
    for (let i = 0; i < 8; i++) {
        res.push(u8_view[offset + i]);
    }
    return new Int(res);
}

// for writes less than 8 bytes
function write(u8_view, offset, value, size) {
    for (let i = 0; i < size; i++) {
        u8_view[offset + i]  = (value >>> i*8) & 0xff;
    }
}

function write16(u8_view, offset, value) {
    write(u8_view, offset, value, 2);
}

function write32(u8_view, offset, value) {
    write(u8_view, offset, value, 4);
}

function write64(u8_view, offset, value) {
    if (!(value instanceof Int)) {
        throw TypeError('write64 value must be an Int');
    }

    let low = value.low();
    let high = value.high();

    for (let i = 0; i < 4; i++) {
        u8_view[offset + i]  = (low >>> i*8) & 0xff;
    }
    for (let i = 0; i < 4; i++) {
        u8_view[offset + 4 + i]  = (high >>> i*8) & 0xff;
    }
}

function sread64(str, offset) {
    let res = [];
    for (let i = 0; i < 8; i++) {
        res.push(str.charCodeAt(offset + i));
    }
    return new Int(res);
}
