package main

import (
	"context"
	"fmt"
	"unicode/utf16"

	"github.com/tetratelabs/wazero/api"
)

const wasmImportModule = "./qoder_auth_wasm_bg.js"

type fakeU8 struct {
	n       int
	buf     []byte
	mem     api.Memory
	ptr     uint32
	memBack bool
}

func (f *fakeU8) read() []byte {
	if f.memBack {
		data, ok := f.mem.Read(f.ptr, uint32(f.n))
		if !ok {
			return nil
		}
		return append([]byte(nil), data...)
	}
	return append([]byte(nil), f.buf...)
}
func (f *fakeU8) write(data []byte) bool {
	if f == nil || len(data) != f.n {
		return false
	}
	if f.memBack {
		return f.mem != nil && f.mem.Write(f.ptr, data)
	}
	copy(f.buf, data)
	return true
}

type nullValue struct{}
type globalValue struct{}
type cryptoValue struct{}
type processValue struct{}
type errorValue struct{}

var undefinedValue any
var nullSentinel any = nullValue{}
var globalSentinel any = globalValue{}
var cryptoSentinel any = cryptoValue{}
var processSentinel any = processValue{}
var versionsSentinel any = map[string]any{"node": "24.3.0"}

func (w *wasmBackend) instantiateHost(ctx context.Context) error {
	builder := w.runtime.NewHostModuleBuilder(wasmImportModule)
	i32, f64 := api.ValueTypeI32, api.ValueTypeF64
	def := func(name string, params, results []api.ValueType, fn func([]uint64)) {
		builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, _ api.Module, stack []uint64) { fn(stack) }), params, results).Export(name)
	}
	p0 := []api.ValueType{}
	p1 := []api.ValueType{i32}
	p2 := []api.ValueType{i32, i32}
	p3 := []api.ValueType{i32, i32, i32}
	r0 := []api.ValueType{}
	r1 := []api.ValueType{i32}
	def("__wbindgen_object_drop_ref", p1, r0, func(s []uint64) { w.drop(uint32(s[0])) })
	def("__wbg_set_08463b1df38a7e29", p3, r1, func(s []uint64) {
		m, k, v := uint32(s[0]), uint32(s[1]), uint32(s[2])
		if target, ok := w.get(m).(map[string]string); ok {
			key, _ := w.get(k).(string)
			value, _ := w.get(v).(string)
			target[key] = value
		}
		s[0] = uint64(w.add(w.get(m)))
	})
	def("__wbg_getRandomValues_d49329ff89a07af1", p2, r0, func(s []uint64) { w.writeEntropy(uint32(s[0]), uint32(s[1])) })
	def("__wbg_getRandomValues_c44a50d8cfdaebeb", p2, r0, func(s []uint64) { w.fillArray(uint32(s[1])) })
	def("__wbg_crypto_38df2bab126b63dc", p1, r1, func(s []uint64) { s[0] = uint64(w.add(cryptoSentinel)) })
	def("__wbg_process_44c7a14e11e9f69e", p1, r1, func(s []uint64) { s[0] = uint64(w.add(processSentinel)) })
	def("__wbg_versions_276b2795b1c6a219", p1, r1, func(s []uint64) { s[0] = uint64(w.add(versionsSentinel)) })
	def("__wbg_node_84ea875411254db1", p1, r1, func(s []uint64) { s[0] = uint64(w.add("24.3.0")) })
	def("__wbg_require_b4edbdcf3e2a1ef0", p0, r1, func(s []uint64) { s[0] = uint64(w.add(cryptoSentinel)) })
	def("__wbg_msCrypto_bd5a034af96bcba6", p1, r1, func(s []uint64) { s[0] = uint64(w.add(cryptoSentinel)) })
	def("__wbg_randomFillSync_6c25eac9869eb53c", p2, r0, func(s []uint64) { idx := uint32(s[1]); defer w.drop(idx); w.fillArray(idx) })
	def("__wbg_call_d578befcc3145dee", p3, r1, func(s []uint64) {
		if w.get(uint32(s[0])) == "getRandomValues" {
			w.fillArray(uint32(s[2]))
		}
		s[0] = 0
	})
	def("__wbindgen_object_clone_ref", p1, r1, func(s []uint64) { s[0] = uint64(w.add(w.get(uint32(s[0])))) })
	def("__wbg_new_with_length_9cedd08484b73942", p1, r1, func(s []uint64) { n := int(uint32(s[0])); s[0] = uint64(w.add(&fakeU8{n: n, buf: make([]byte, n)})) })
	def("__wbg_length_0c32cb8543c8e4c8", p1, r1, func(s []uint64) {
		switch value := w.get(uint32(s[0])).(type) {
		case *fakeU8:
			s[0] = uint64(value.n)
		case string:
			s[0] = uint64(len(utf16.Encode([]rune(value))))
		default:
			s[0] = 0
		}
	})
	def("__wbg_prototypesetcall_3e05eb9545565046", p3, r0, func(s []uint64) {
		ptr, n, idx := uint32(s[0]), uint32(s[1]), uint32(s[2])
		array, ok := w.get(idx).(*fakeU8)
		if !ok || array.n != int(n) || !w.mem.Write(ptr, array.read()) {
			w.hostFail = fail("host-array")
		}
	})
	def("__wbg_subarray_0f98d3fb634508ad", p3, r1, func(s []uint64) {
		idx, begin, end := uint32(s[0]), uint32(s[1]), uint32(s[2])
		array, ok := w.get(idx).(*fakeU8)
		if !ok || end < begin || end > uint32(array.n) {
			w.hostFail = fail("host-subarray")
			s[0] = uint64(w.add(&fakeU8{}))
			return
		}
		if array.memBack {
			s[0] = uint64(w.add(&fakeU8{n: int(end - begin), mem: w.mem, ptr: array.ptr + begin, memBack: true}))
			return
		}
		s[0] = uint64(w.add(&fakeU8{n: int(end - begin), buf: array.read()[begin:end]}))
	})
	def("__wbg_new_99cabae501c0a8a0", p0, r1, func(s []uint64) { s[0] = uint64(w.add(map[string]string{})) })
	def("__wbg_now_88621c9c9a4f3ffc", p0, []api.ValueType{f64}, func(s []uint64) {
		if w.replay == nil {
			w.hostFail = fail("transcript-missing")
			s[0] = api.EncodeF64(0)
			return
		}
		now, err := w.replay.Now()
		if err != nil {
			w.hostFail = err
			s[0] = api.EncodeF64(0)
			return
		}
		s[0] = api.EncodeF64(float64(now.UnixMilli()))
	})
	for _, name := range []string{"__wbg_static_accessor_GLOBAL_THIS_a1248013d790bf5f", "__wbg_static_accessor_SELF_24f78b6d23f286ea", "__wbg_static_accessor_GLOBAL_f2e0f995a21329ff"} {
		name := name
		def(name, p0, r1, func(s []uint64) { s[0] = uint64(w.add(globalSentinel)) })
	}
	def("__wbg_static_accessor_WINDOW_59fd959c540fe405", p0, r1, func(s []uint64) { s[0] = 0 })
	def("__wbg___wbindgen_throw_81fc77679af83bc6", p2, r0, func(s []uint64) { w.hostFail = fail("wasm-throw") })
	def("__wbg_Error_2e59b1b37a9a34c3", p2, r1, func(s []uint64) { s[0] = uint64(w.add(errorValue{})) })
	def("__wbg___wbindgen_is_object_40c5a80572e8f9d3", p1, r1, func(s []uint64) {
		v := w.get(uint32(s[0]))
		_, m := v.(map[string]string)
		_, u := v.(*fakeU8)
		_, g := v.(globalValue)
		_, c := v.(cryptoValue)
		_, p := v.(processValue)
		_, vs := v.(map[string]any)
		if (m || u || g || c || p || vs) && v != nullSentinel {
			s[0] = 1
		} else {
			s[0] = 0
		}
	})
	def("__wbg___wbindgen_is_string_b29b5c5a8065ba1a", p1, r1, func(s []uint64) {
		if _, ok := w.get(uint32(s[0])).(string); ok {
			s[0] = 1
		} else {
			s[0] = 0
		}
	})
	def("__wbg___wbindgen_is_function_49868bde5eb1e745", p1, r1, func(s []uint64) { s[0] = 0 })
	def("__wbg___wbindgen_is_undefined_c0cca72b82b86f4d", p1, r1, func(s []uint64) {
		if w.get(uint32(s[0])) == undefinedValue {
			s[0] = 1
		} else {
			s[0] = 0
		}
	})
	def("__wbindgen_cast_0000000000000001", p2, r1, func(s []uint64) {
		ptr, n := uint32(s[0]), uint32(s[1])
		s[0] = uint64(w.add(&fakeU8{n: int(n), mem: w.mem, ptr: ptr, memBack: true}))
	})
	def("__wbindgen_cast_0000000000000002", p2, r1, func(s []uint64) { s[0] = uint64(w.add(w.readString(uint32(s[0]), uint32(s[1])))) })
	module, err := builder.Instantiate(ctx)
	if err != nil {
		return fmt.Errorf("instantiate host: %w", err)
	}
	w.hostModule = module
	return nil
}
func (w *wasmBackend) writeEntropy(ptr, length uint32) {
	buf := make([]byte, length)
	if w.replay == nil {
		w.hostFail = fail("transcript-missing")
	} else if err := w.replay.Read(buf); err != nil {
		w.hostFail = err
	}
	if w.hostFail != nil {
		for i := range buf {
			buf[i] = 1
		}
	}
	if !w.mem.Write(ptr, buf) {
		w.hostFail = fail("host-memory")
	}
}
func (w *wasmBackend) fillArray(index uint32) {
	array, ok := w.get(index).(*fakeU8)
	if !ok {
		w.hostFail = fail("host-array")
		return
	}
	buf := make([]byte, array.n)
	if w.replay == nil {
		w.hostFail = fail("transcript-missing")
	} else if err := w.replay.Read(buf); err != nil {
		w.hostFail = err
	}
	if w.hostFail != nil {
		for i := range buf {
			buf[i] = 1
		}
	}
	if !array.write(buf) {
		w.hostFail = fail("host-array")
	}
}
