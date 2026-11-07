import type { Manifest } from "../model/manifest.js";
import type { Policy } from "../model/policy.js";
import type { AssuranceReport } from "../model/evidence.js";
import type { Loaded } from "../util/io.js";
import { type AuthzResults } from "../lanes/authorization.js";
import { type Limits } from "../lanes/containers.js";
import { type ExternalImport } from "../lanes/external.js";
export interface AssureInput {
    readonly manifest: Loaded<Manifest>;
    readonly policy: Loaded<Policy>;
    readonly authzResults?: AuthzResults | null;
    /** Findings from dedicated scanners run over the same release (see lanes/external.ts). */
    readonly imports?: readonly ExternalImport[];
    readonly limits?: Limits;
}
/**
 * The end-to-end pipeline (doc §9):
 *   release inventory & identity → asset objectives → static exposure +
 *   placement + authorization lanes → coverage reconciliation → hard gates.
 */
export declare function assure(input: AssureInput): AssuranceReport;
