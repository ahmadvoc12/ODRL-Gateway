import { readFile } from 'fs/promises';
import path from 'path';

export async function renderAgreement(clientId: string) {
  const ttl = await readFile(
    path.join(process.cwd(), 'storage/agreements', `${clientId}.ttl`),
    'utf-8'
  );

  return `
<!DOCTYPE html>
<html>
<head>
  <title>Consent Agreement</title>
</head>
<body>
  <h1>Authorization Agreement</h1>
  <p>This agreement defines how your data may be accessed.</p>

  <pre>${ttl}</pre>

  <button onclick="window.location.href='/'">
    Continue
  </button>
</body>
</html>
`;
}
