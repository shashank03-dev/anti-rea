import type { AssuranceReport, Finding } from "../model/evidence.js";
export declare function locationText(f: Finding): string;
export declare function renderMarkdown(rep: AssuranceReport): string;
export declare function writeReport(rep: AssuranceReport, outDir: string): {
    json: string;
    md: string;
};
export declare function renderSummary(rep: AssuranceReport): string;
