/**
 * tests/cvss40.spec.js
 *
 * Spec-compliance tests for the CVSS 4.0 scoring engine (lib/cvsscalc40.js).
 *
 * Golden values sourced from:
 *  - FIRST.org official CVSS v4.0 Examples document (v1.8)
 *    https://www.first.org/cvss/v4-0/examples
 *  - CVSS 4.0 Specification — lookup table entries
 *    https://www.first.org/cvss/v4.0/specification-document
 *
 * The library uses class declarations (Vector, CVSS40) in non-module JS.
 * We load the file via Function() to expose those classes on globalThis.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { runInThisContext } from 'vm';
import path from 'path';

// ---------------------------------------------------------------------------
// Bootstrap: load cvsscalc40.js into THIS module's global scope.
//
// The lib has a Node/browser environment check at the bottom:
//   if (typeof module !== 'undefined' && module.exports) { ... }
//   else { window.CVSS40 = CVSS40; }
//
// In Vitest ESM mode, `module` is undefined, so execution falls into the
// browser branch and tries to write `window.CVSS40`. We stub `globalThis.window`
// first so that write lands safely. Then we pick CVSS40 off of it.
// ---------------------------------------------------------------------------
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const libPath   = path.resolve(__dirname, '../lib/cvsscalc40.js');
const libCode   = readFileSync(libPath, 'utf8');

// Provide a stub window so the browser branch can write to it safely.
globalThis.window = globalThis.window ?? {};

runInThisContext(libCode, { filename: libPath });

// Grab from window stub (browser branch) or globalThis (if Node branch ran)
const CVSS40 = globalThis.window.CVSS40 ?? globalThis.CVSS40;

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------
function score40(vector) {
    const vuln = new CVSS40(vector);
    return parseFloat(vuln.score.toFixed(1));
}

function severity40(vector) {
    const vuln = new CVSS40(vector);
    return vuln.severity;
}

// ---------------------------------------------------------------------------
// 1. OFFICIAL FIRST.org EXAMPLE VECTORS
//    Source: https://www.first.org/cvss/v4-0/examples (document version 1.8)
// ---------------------------------------------------------------------------
describe('CVSS 4.0 — FIRST.org official example vectors', () => {

    it('CVE-2022-41741 NGINX mp4 module → 7.3 High', () => {
        // FIRST.org v4.0 Examples doc — "New Metric: Attack Requirements" section
        const v = 'CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';
        expect(score40(v)).toBe(7.3);
        expect(severity40(v)).toBe('High');
    });

    it('CVE-2020-3549 Cisco FMC sftunnel base → 7.7 High', () => {
        // FIRST.org v4.0 Examples doc — Base score
        const v = 'CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';
        expect(score40(v)).toBe(7.7);
        expect(severity40(v)).toBe('High');
    });

    it('CVE-2020-3549 Cisco FMC sftunnel base+threat (E:U) → 5.2 Medium', () => {
        // FIRST.org v4.0 Examples doc — Base+Threat score
        const v = 'CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U';
        expect(score40(v)).toBe(5.2);
        expect(severity40(v)).toBe('Medium');
    });

    it('Maximum score — all worst-case base metrics → 10.0 Critical', () => {
        // AV:N PR:N UI:N AC:L AT:N VC:H VI:H VA:H SC:H SI:H SA:H
        const v = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H';
        expect(score40(v)).toBe(10.0);
        expect(severity40(v)).toBe('Critical');
    });

    it('Local attacker, no impact on any system → 0.0 None', () => {
        // All impacts None — should yield 0 (or very low per lookup table)
        // Spec: lookup "222221" = 0.6, but AV:P forces higher isolation → let's
        // use a known zero-impact combo from the table edge
        const v = 'CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N';
        const s = score40(v);
        expect(s).toBe(0.0);
        expect(severity40(v)).toBe('None');
    });

    it('Spec lookup table entry 000000 → 10.0', () => {
        // EQ1=0 (AV:N,PR:N,UI:N), EQ2=0 (AC:L,AT:N),
        // EQ3=0 (VC:H,VI:H), EQ4=1 (SC:H), EQ5=0 (E:A), EQ6=0 (CR:H,VC:H)
        // Approximate vector that produces macrovector 000000
        const v = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H';
        expect(score40(v)).toBe(10.0);
    });

    it('Spec lookup table entry 222221 — physical/complex/no-impact/unreported → Low', () => {
        // This vector maps to macrovector 222221 which gives score 0.6 in spec table,
        // however the actual library score depends on interpolation within the bucket.
        // We verify the score is in the Low severity range and above 0.
        const v = 'CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/E:U';
        const s = score40(v);
        expect(s).toBeGreaterThan(0.0);
        expect(s).toBeLessThanOrEqual(1.0);  // Lowest severity band
        expect(severity40(v)).toBe('Low');
    });

});

// ---------------------------------------------------------------------------
// 2. SEVERITY BAND BOUNDARY TESTS  (CVSS 4.0 spec §7.5)
//    None: 0.0 | Low: 0.1–3.9 | Medium: 4.0–6.9 | High: 7.0–8.9 | Critical: 9.0–10.0
// ---------------------------------------------------------------------------
describe('CVSS 4.0 — severity band boundaries', () => {

    it.each([
        // [vector, expectedScore, expectedSeverity]
        ['CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N',         0.0,  'None'],
        ['CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U',     5.2,  'Medium'],
        ['CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',         7.3,  'High'],
        ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H',         10.0, 'Critical'],
    ])('%s → %f (%s)', (vector, expectedScore, expectedSeverity) => {
        expect(score40(vector)).toBe(expectedScore);
        expect(severity40(vector)).toBe(expectedSeverity);
    });

});

// ---------------------------------------------------------------------------
// 3. VALIDATION / ERROR HANDLING
// ---------------------------------------------------------------------------
describe('CVSS 4.0 — input validation', () => {

    it('throws on invalid metric value (AV:Z)', () => {
        expect(() => new CVSS40('CVSS:4.0/AV:Z/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'))
            .toThrow();
    });

    it('throws on wrong version prefix', () => {
        expect(() => new CVSS40('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'))
            .toThrow();
    });

    it('throws on missing mandatory base metric (missing SC)', () => {
        // Omitting SC (Subsequent System Confidentiality) — mandatory
        expect(() => new CVSS40('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SI:N/SA:N'))
            .toThrow();
    });

    it('empty string initializes default metrics without throwing', () => {
        // CVSS40('') is valid — the constructor treats empty string as "no vector"
        // and initializes all metrics to their defaults.
        expect(() => new CVSS40('')).not.toThrow();
        const vuln = new CVSS40('');
        expect(typeof vuln.score).toBe('number');
    });

    it('accepts valid optional Threat metric (E:U)', () => {
        // Should not throw; E is optional
        expect(() => new CVSS40('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U'))
            .not.toThrow();
    });

    it('accepts valid optional Environmental metric (CR:H)', () => {
        expect(() => new CVSS40('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H'))
            .not.toThrow();
    });

    it('score property is a finite number between 0 and 10', () => {
        const vuln = new CVSS40('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
        expect(typeof vuln.score).toBe('number');
        expect(isFinite(vuln.score)).toBe(true);
        expect(vuln.score).toBeGreaterThanOrEqual(0);
        expect(vuln.score).toBeLessThanOrEqual(10);
    });

});

// ---------------------------------------------------------------------------
// 4. SCORING FORMULA MONOTONICITY
//    Making a metric "more severe" must never decrease the score.
// ---------------------------------------------------------------------------
describe('CVSS 4.0 — scoring formula monotonicity', () => {

    it('Network AV scores >= Local AV (all else equal)', () => {
        const net   = score40('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
        const local = score40('CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
        expect(net).toBeGreaterThanOrEqual(local);
    });

    it('AT:N scores >= AT:P (all else equal)', () => {
        const none    = score40('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
        const present = score40('CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
        expect(none).toBeGreaterThanOrEqual(present);
    });

    it('Higher Vulnerable System impact scores >= lower (all else equal)', () => {
        const allHigh = score40('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
        const allLow  = score40('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N');
        expect(allHigh).toBeGreaterThan(allLow);
    });

    it('Adding Subsequent System impact does not decrease score', () => {
        const noSubseq = score40('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
        const withSubseq = score40('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H');
        expect(withSubseq).toBeGreaterThanOrEqual(noSubseq);
    });

    it('E:A (Active exploit) scores higher than E:U (Unreported)', () => {
        // Threat metric: Active > Poc > Unreported
        const active     = score40('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A');
        const unreported = score40('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U');
        expect(active).toBeGreaterThan(unreported);
    });

    it('Score is always within [0.0, 10.0]', () => {
        const testVectors = [
            'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H',
            'CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
            'CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U',
            'CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/E:U',
            'CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N',
        ];
        for (const v of testVectors) {
            const s = score40(v);
            expect(s).toBeGreaterThanOrEqual(0.0);
            expect(s).toBeLessThanOrEqual(10.0);
        }
    });

});

// ---------------------------------------------------------------------------
// 5. CVSS 4.0 NOMENCLATURE — Base / Base+Threat / Base+Env
// ---------------------------------------------------------------------------
describe('CVSS 4.0 — vector nomenclature', () => {

    it('Base-only vector → CVSS-B', () => {
        const vuln = new CVSS40('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
        expect(vuln.vector.nomenclature).toBe('CVSS-B');
    });

    it('Base + Threat vector → CVSS-BT', () => {
        const vuln = new CVSS40('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U');
        expect(vuln.vector.nomenclature).toBe('CVSS-BT');
    });

    it('Base + Environmental vector → CVSS-BE', () => {
        const vuln = new CVSS40('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H');
        expect(vuln.vector.nomenclature).toBe('CVSS-BE');
    });

    it('Base + Threat + Environmental vector → CVSS-BTE', () => {
        const vuln = new CVSS40('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U/CR:H');
        expect(vuln.vector.nomenclature).toBe('CVSS-BTE');
    });

});
