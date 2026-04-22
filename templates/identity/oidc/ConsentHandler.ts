import { createAgreement } from '../account/agreement/AgreementService';

export async function afterConsent({
  webId,
  client,
  redirect,
}: any) {
  await createAgreement({ webId, client });

  // arahkan ke halaman agreement
  return {
    location: `/.account/agreements/${client.client_id}`,
  };
}
