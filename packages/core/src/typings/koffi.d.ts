/** Minimal type stub for koffi — optional dependency, only used on Windows. */
declare module "koffi" {
	function load(path: string): KoffiLibrary;
	function pointer(name: string, type: unknown): unknown;
	function opaque(): unknown;

	interface KoffiLibrary {
		/* biome-ignore lint/suspicious/noExplicitAny: koffi FFI functions have dynamic signatures */
		func(signature: string): (...args: any[]) => any;
	}
}
