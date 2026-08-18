/**
 * tests/cvss31.spec.js
 *
 * Spec-compliance tests for the CVSS 3.1 scoring engine (lib/cvsscalc31.js).
 *
 * Golden values sourced from:
 *  - FIRST.org official CVSS v3.1 Examples document
 *    https://www.first.org/cvss/v3.1/examples
 *  - FIRST.org CVSS v3.1 Specification Document (Appendix A)
 *    https://www.first.org/cvss/v3.1/specification-document
 *
 * The library uses the `var CVSS31 = {}` global pattern, so we
 * load it via Node's createRequire shim that injects a global scope.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { runInThisContext } from 'vm';
import path from 'path';

// ---------------------------------------------------------------------------
// Bootstrap: load cvsscalc31.js into THIS module's global scope.
// vm.runInThisContext() runs code as if at top level of the current Node
// context, so `var CVSS31 = {}` leaks onto globalThis correctly.
// ---------------------------------------------------------------------------
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const libPath   = path.resolve(__dirname, '../lib/cvsscalc31.js');
const libCode   = readFileSync(libPath, 'utf8');

runInThisContext(libCode, { filename: libPath });

const { CVSS31 } = globalThis;

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------
function score31(vector) {
    const r = CVSS31.calculateCVSSFromVector(vector);
    if (!r.success) throw new Error(`CVSS31 failed for "${vector}": ${r.errorType}`);
    return parseFloat(r.baseMetricScore);
}

function severity31(vector) {
    const r = CVSS31.calculateCVSSFromVector(vector);
    if (!r.success) throw new Error(`CVSS31 failed for "${vector}": ${r.errorType}`);
    return r.baseSeverity;
}

// ---------------------------------------------------------------------------
// 1. OFFICIAL FIRST.org EXAMPLE VECTORS
//    Sources:
//      v3.1 Examples doc — CVE-2013-0375, CVE-2014-3566 etc.
//      Specification appendix — canonical boundary scores
// ---------------------------------------------------------------------------
describe('CVSS 3.1 — FIRST.org official example vectors', () => {

    it('CVE-2013-0375 MySQL SQL Injection → 6.4 Medium', () => {
        // FIRST.org v3.1 Examples doc, Section 3
        // AV:N AC:L PR:L UI:N S:C C:L I:L A:N
        const v = 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N';
        expect(score31(v)).toBe(6.4);
        expect(severity31(v)).toBe('Medium');
    });

    it('CVE-2014-3566 POODLE → 3.4 Low', () => {
        // FIRST.org v3.1 Examples doc, Section 4
        // AV:N AC:H PR:N UI:R S:C C:L I:N A:N
        const v = 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N';
        expect(score31(v)).toBe(3.4);
        expect(severity31(v)).toBe('Low');
    });

    it('Heartbleed-class critical network RCE → 9.8 Critical', () => {
        // AV:N AC:L PR:N UI:N S:U C:H I:H A:H — canonical "worst case" base
        const v = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
        expect(score31(v)).toBe(9.8);
        expect(severity31(v)).toBe('Critical');
    });

    it('Scope-Changed critical → 10.0 Critical', () => {
        // Scope changed pushes max beyond 10 → clamped to 10.0
        const v = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H';
        expect(score31(v)).toBe(10.0);
        expect(severity31(v)).toBe('Critical');
    });

    it('Local high-complexity privileged → 6.4 Medium', () => {
        // AV:L AC:H PR:H UI:N S:U C:H I:H A:H
        const v = 'CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H';
        expect(score31(v)).toBe(6.4);
        expect(severity31(v)).toBe('Medium');
    });

    it('Physical access, no impact → 0.0 None', () => {
        // AV:P AC:H PR:H UI:R S:U C:N I:N A:N
        const v = 'CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N';
        expect(score31(v)).toBe(0.0);
        expect(severity31(v)).toBe('None');
    });

    it('Network, low complexity, no privs, no UI, availability only → 7.5 High', () => {
        // AV:N AC:L PR:N UI:N S:U C:N I:N A:H
        const v = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H';
        expect(score31(v)).toBe(7.5);
        expect(severity31(v)).toBe('High');
    });

    it('CVE-2022-41741 NGINX mp4 module (v3.1 side) → 7.0 High', () => {
        // From FIRST.org v4.0 Examples doc, comparison table
        const v = 'CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H';
        expect(score31(v)).toBe(7.0);
        expect(severity31(v)).toBe('High');
    });

    it('CVE-2020-3549 Cisco FMC sftunnel (v3.1 side) → 8.1 High', () => {
        // From FIRST.org v4.0 Examples doc, comparison table
        // AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H  (note A:H, not A:N)
        const v = 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H';
        expect(score31(v)).toBe(8.1);
        expect(severity31(v)).toBe('High');
    });

});

// ---------------------------------------------------------------------------
// 2. SEVERITY BAND BOUNDARY TESTS
//    Verifies exact scoring thresholds from specification §7.5
// ---------------------------------------------------------------------------
describe('CVSS 3.1 — severity band boundary compliance', () => {

    it.each([
        // [score, expectedSeverity]
        // None: 0.0
        [0.0,  'None'],
        // Low: 0.1 – 3.9
        [0.1,  'Low'],
        [3.9,  'Low'],
        // Medium: 4.0 – 6.9
        [4.0,  'Medium'],
        [6.9,  'Medium'],
        // High: 7.0 – 8.9
        [7.0,  'High'],
        [8.9,  'High'],
        // Critical: 9.0 – 10.0
        [9.0,  'Critical'],
        [10.0, 'Critical'],
    ])('score %f → %s', (score, expected) => {
        expect(CVSS31.severityRating(score.toFixed(1))).toBe(expected);
    });

});

// ---------------------------------------------------------------------------
// 3. VALIDATION / ERROR HANDLING
// ---------------------------------------------------------------------------
describe('CVSS 3.1 — input validation', () => {

    it('returns success:false for an invalid metric value (AV:Z)', () => {
        const r = CVSS31.calculateCVSSFromVector('CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
        expect(r.success).toBe(false);
        expect(r.errorType).toBe('MalformedVectorString');
    });

    it('returns success:false for a missing base metric', () => {
        // Missing A (Availability)
        const r = CVSS31.calculateCVSSFromVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H');
        expect(r.success).toBe(false);
    });

    it('returns success:false for wrong version prefix', () => {
        const r = CVSS31.calculateCVSSFromVector('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
        expect(r.success).toBe(false);
    });

    it('returns success:false for duplicate metric definition', () => {
        const r = CVSS31.calculateCVSSFromVector('CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
        expect(r.success).toBe(false);
        expect(r.errorType).toBe('MultipleDefinitionsOfMetric');
    });

    it('calculates from metrics API and matches vector API', () => {
        const fromMetrics = CVSS31.calculateCVSSFromMetrics(
            'N', 'L', 'N', 'N', 'U', 'H', 'H', 'H',
            'X', 'X', 'X',
            'X', 'X', 'X', 'X', 'X', 'X', 'X', 'X', 'X', 'X', 'X'
        );
        const fromVector = CVSS31.calculateCVSSFromVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
        expect(fromMetrics.success).toBe(true);
        expect(fromMetrics.baseMetricScore).toBe(fromVector.baseMetricScore);
    });

});

// ---------------------------------------------------------------------------
// 4. SCORING FORMULA SANITY CHECKS
//    These assert spec-defined monotonicity: making a metric "worse" must
//    never decrease the score (or vice versa).
// ---------------------------------------------------------------------------
describe('CVSS 3.1 — scoring formula monotonicity', () => {

    it('Network AV scores higher than Local AV (all else equal)', () => {
        const net   = score31('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
        const local = score31('CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
        expect(net).toBeGreaterThan(local);
    });

    it('Low AC scores higher than High AC (all else equal)', () => {
        const low  = score31('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
        const high = score31('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H');
        expect(low).toBeGreaterThan(high);
    });

    it('No PR scores higher than High PR (all else equal)', () => {
        const none = score31('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
        const high = score31('CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H');
        expect(none).toBeGreaterThan(high);
    });

    it('Scope:Changed scores higher than Scope:Unchanged (all else equal)', () => {
        const changed   = score31('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L');
        const unchanged = score31('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L');
        expect(changed).toBeGreaterThan(unchanged);
    });

    it('High CIA scores higher than Low CIA (all else equal)', () => {
        const allHigh = score31('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
        const allLow  = score31('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L');
        expect(allHigh).toBeGreaterThan(allLow);
    });

    it('Score is always within [0.0, 10.0]', () => {
        const testVectors = [
            'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
            'CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N',
            'CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N',
            'CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:H',
        ];
        for (const v of testVectors) {
            const s = score31(v);
            expect(s).toBeGreaterThanOrEqual(0.0);
            expect(s).toBeLessThanOrEqual(10.0);
        }
    });

});
