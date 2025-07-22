declare module "crc-32" {
  interface CRC32 {
    str: (input: string, initial?: number) => number;
    buf: (input: Uint8Array | number[], initial?: number) => number;
    bstr: (input: string, initial?: number) => number;
  }

  const crc32: CRC32;
  export = crc32;
}