declare namespace RootGuard {
    type Status = 0 | 1 | 2;

    interface DetailedResult {
        status: Status;
        statusName: "SAFE" | "COMPROMISED" | "UNKNOWN";
        platform: "android" | "ios";
        osVersion: string;
        apiLevel?: number;
        evidence: string[];
        unavailableChecks: string[];
        localOnly: true;
    }

    interface Plugin {
        readonly SAFE: 0;
        readonly COMPROMISED: 1;
        readonly UNKNOWN: 2;

        checkSecurity(
            success: (compromised: 0 | 1) => void,
            error?: (error: unknown) => void
        ): void;

        checkSecurityStatus(
            success: (status: Status) => void,
            error?: (error: unknown) => void
        ): void;

        checkSecurityDetailed(
            success: (result: DetailedResult) => void,
            error?: (error: unknown) => void
        ): void;
    }
}

declare const RootGuard: RootGuard.Plugin;
export = RootGuard;
export as namespace RootGuard;
