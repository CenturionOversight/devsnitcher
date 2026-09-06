import type { SnitchUiState } from '../../shared/types';

/**
 * Popup lifecycle state: the background-authoritative states plus the
 * popup-local transient `copying` transition (the OS clipboard write).
 */
export type PopupCtaState = SnitchUiState | 'copying';

export interface CtaConfig {
  /** Whether the SNITCH action is enabled and clickable. */
  snitchEnabled: boolean;
  /** Whether the upper-right close control is visible (only while acquiring). */
  closeVisible: boolean;
  /** Whether COPY SNITCHSHOT is enabled (only when a report is pending). */
  copyEnabled: boolean;
  /** Whether the SNITCH configuration inputs are editable. */
  inputsEnabled: boolean;
  /** Contextual label under SNITCH. */
  snitchLabel: string;
  /** Contextual label under COPY SNITCHSHOT. */
  copyLabel: string;
}

/**
 * Deterministic single-projection of the lifecycle onto the two primary CTAs
 * and the upper-right acquisition close control (×).
 *
 * All visible controls stay rendered; the state only decides which are enabled,
 * which are hidden, and what contextual label each shows, so the popup can
 * never present two contradictory "active" actions at the same time. This is
 * the ONLY place the population of the CTA configuration is derived — no
 * separate UI bits are allowed to disagree with it.
 *
 * Contract per background lifecycle:
 *
 *   IDLE              → only SNITCH enabled; × hidden
 *   OBSERVING         → SNITCH and COPY unavailable; × visible and actionable
 *   SNITCHSHOT_PENDING→ only COPY SNITCHSHOT enabled; × hidden
 *   COPYING (local)   → nothing enabled; COPY shows progress "Copying…"; × hidden
 */
export function ctaConfig(state: PopupCtaState): CtaConfig {
  switch (state) {
    case 'idle':
      return {
        snitchEnabled: true,
        closeVisible: false,
        copyEnabled: false,
        inputsEnabled: true,
        snitchLabel: 'Ready',
        copyLabel: 'No report',
      };
    case 'observing':
      return {
        snitchEnabled: false,
        closeVisible: true,
        copyEnabled: false,
        inputsEnabled: false,
        snitchLabel: 'Watching…',
        copyLabel: 'Not ready',
      };
    case 'snitchshot_pending':
      return {
        snitchEnabled: false,
        closeVisible: false,
        copyEnabled: true,
        inputsEnabled: false,
        snitchLabel: 'Report pending',
        copyLabel: 'Send report to clipboard',
      };
    case 'copying':
      return {
        snitchEnabled: false,
        closeVisible: false,
        copyEnabled: false,
        inputsEnabled: false,
        snitchLabel: 'Report pending',
        copyLabel: 'Copying…',
      };
  }
}