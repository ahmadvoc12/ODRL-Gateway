import type { Request, Response } from 'express';

export async function monitorPreview(req: Request, res: Response): Promise<void> {
  try {
    const interaction = (req as any).oidc?.interactionDetails;

    if (!interaction) {
      res.status(400).json({ error: 'OIDC interaction not found' });
      return;
    }

    const params = interaction.params ?? {};
    const scope: string = params.scope ?? '';

    const scopes = scope.split(' ').filter(Boolean);

    const permissions = {
      read: scopes.some(s => ['openid', 'profile', 'webid'].includes(s)),
      write: scopes.includes('solid:write'),
      append: scopes.includes('solid:append'),
      control: scopes.includes('solid:control'),
    };

    let risk: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW';
    if (permissions.control) risk = 'HIGH';
    else if (permissions.write || permissions.append) risk = 'MEDIUM';

    res.json({
      client_id: params.client_id,
      redirect_uri: params.redirect_uri,
      requested_scope: scopes,
      inferred_permissions: permissions,
      risk_level: risk,
      preview: true
    });

  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
}
