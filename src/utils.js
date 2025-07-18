/**
 * Sanitizes a Space DID for use as a KMS key ID
 * @param {string} spaceDID - The Space DID to sanitize
 * @returns {string} - The sanitized key ID
 * @throws {Error} - If the Space DID format is invalid
 */
export function sanitizeSpaceDIDForKMSKeyId (spaceDID) {
  // Remove the did:key: prefix
  const keyId = spaceDID.replace(/^did:key:/, '')

  // Space DIDs are always exactly 48 characters after removing the prefix
  // This is more restrictive than Google KMS's 1-63 limit, but matches the actual format
  if (keyId.length !== 48) {
    throw new Error('Invalid Space DID format. Expected exactly 48 characters after removing did:key: prefix.')
  }

  // Validate character set (letters and numbers only)
  if (!/^[a-zA-Z0-9]+$/.test(keyId)) {
    throw new Error('Invalid Space DID format. Must contain only letters and numbers.')
  }

  return keyId
}
