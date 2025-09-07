export type Disclosure = string;
export declare function makeDisclosure(name: string, value: unknown, salt?: Uint8Array): Disclosure;
export declare function digestDisclosure(disclosure: Disclosure): string;
export declare function parseDisclosure(disclosure: Disclosure): {
    saltB64u: string;
    name: string;
    value: unknown;
};
