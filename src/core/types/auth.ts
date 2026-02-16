export interface TokenClaims {
  tokenId: string;
  subject: string;
  tenantIds: string[];
  scopes: string[];
  role: "admin" | "operator" | "auditor" | "agent" | "service";
  delegationChain?: string[] | undefined;
  serviceAccountId?: string | undefined;
  issuer?: string | undefined;
  tokenType?: "static" | "jwt";
}

export interface AuthContext {
  claims: TokenClaims;
}
