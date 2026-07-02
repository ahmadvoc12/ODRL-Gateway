export function enforceAgreement({
  agreement,
  request,
}: any) {

  if (request.method === 'DELETE' && !agreement.allows('control')) {
    throw new Error('Blocked by agreement');
  }

  if (request.method === 'PUT' && !agreement.allows('write')) {
    throw new Error('Write not permitted');
  }

  if (request.method === 'GET' && !agreement.allows('read')) {
    throw new Error('Read not permitted');
  }
}
