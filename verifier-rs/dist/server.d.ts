type IssuerClient = {
    getJson: (path: string) => Promise<any>;
    getWithMeta?: (path: string, headers?: Record<string, string>) => Promise<{
        body: any;
        headers: Record<string, any>;
        status?: number;
    }>;
};
export declare function buildServer(issuerBase?: string, issuerClient?: IssuerClient): import("fastify").FastifyInstance<import("http").Server<typeof import("http").IncomingMessage, typeof import("http").ServerResponse>, import("http").IncomingMessage, import("http").ServerResponse<import("http").IncomingMessage>, import("fastify").FastifyBaseLogger, import("fastify").FastifyTypeProviderDefault> & PromiseLike<import("fastify").FastifyInstance<import("http").Server<typeof import("http").IncomingMessage, typeof import("http").ServerResponse>, import("http").IncomingMessage, import("http").ServerResponse<import("http").IncomingMessage>, import("fastify").FastifyBaseLogger, import("fastify").FastifyTypeProviderDefault>> & {
    __linterBrands: "SafePromiseLike";
};
export {};
