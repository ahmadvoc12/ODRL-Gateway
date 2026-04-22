import { writeFile } from 'fs/promises';

export async function storeAgreementToPod({
  podRoot,
  client,
  webId,
}: any) {

  const ttl = `
@prefix odrl: <http://www.w3.org/ns/odrl/2/>.
@prefix dpv: <https://w3id.org/dpv#>.
@prefix foaf: <http://xmlns.com/foaf/0.1/>.

<#agreement>
  a odrl:Agreement ;
  odrl:assigner <${webId}> ;
  odrl:assignee <${client.client_uri || client.redirect_uris?.[0]}> ;

  odrl:permission [
    odrl:action dpv:Read ;
    odrl:target foaf:Person ;
  ] ;

  dpv:hasRisk dpv:LowRisk ;
  dpv:hasLegalBasis dpv:Consent .
`;

  const path = `${podRoot}/agreements/${client.client_id}.ttl`;

  await writeFile(path, ttl, 'utf8');
  return path;
}
