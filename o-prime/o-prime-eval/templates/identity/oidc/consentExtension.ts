import { enableMonitoring } from '../../../src/monitoring/monitoringState';

export function extendConsent(consent, payload) {
  if (payload.monitoring === true) {
    enableMonitoring(consent.client.client_id);
  }
}
