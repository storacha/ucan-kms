declare module "fast-crc32c" {
  interface CRC32C {
    calculate: (input: string | Buffer, initial?: number) => number;
    signed: (input: string | Buffer) => number;
    unsigned: (input: string | Buffer) => number;
  }

  const crc32c: CRC32C;
  export = crc32c;
}
