
# Google KMS Setup

This guide walks you through setting up Google KMS for the UCAN KMS service, including both Google Cloud configuration and Cloudflare Worker deployment.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Google Cloud Setup](#google-cloud-setup)
- [Cloudflare Worker Configuration](#cloudflare-worker-configuration)
- [Validation](#validation)
- [Troubleshooting](#troubleshooting)

## Prerequisites

Before starting, ensure you have:

- Google Cloud CLI (`gcloud`) installed and configured
- Access to the Storacha Google Cloud organization
- Cloudflare Workers CLI (`wrangler`) installed
- Required permissions:
  - Project Editor or Owner role in the target Google Cloud project
  - Ability to create IAM roles and service accounts
  - Cloudflare account with Workers access

## Google Cloud Setup

### 1. Authentication

Use the Storacha account for authentication:

```sh
gcloud login
```

### 2. Select Target Project

List available projects:

```sh
gcloud projects list
```

Set your target project (replace `<PROJECT_ID>` with your actual project ID):

```bash
gcloud config set project <PROJECT_ID>
```

**Note**: For staging environment, use `storacha-staging`. For production, use the `storacha-production` project ID.

### 3. Create Service Account

```sh
gcloud iam service-accounts create ucan-kms-sa \
    --display-name="UCAN KMS Service Account" \
    --description="Service account for UCAN KMS operations"
```

### 4. Create Custom KMS Role

This custom role provides minimal permissions for the UCAN KMS service to create and retrieve keys, without key removal permissions:

```sh
gcloud iam roles create kmsKeyCreator \
  --project=<PROJECT_ID> \
  --title="Cloud KMS CryptoKey Creator" \
  --description="Minimal permissions to create KMS keys & versions" \
  --permissions=\
cloudkms.keyRings.get,\
cloudkms.keyRings.list,\
cloudkms.cryptoKeys.create,\
cloudkms.cryptoKeys.get,\
cloudkms.cryptoKeys.list,\
cloudkms.cryptoKeyVersions.create,\
cloudkms.cryptoKeyVersions.get,\
cloudkms.cryptoKeyVersions.list,\
cloudkms.cryptoKeyVersions.viewPublicKey,\
cloudkms.locations.get,\
cloudkms.locations.list,\
resourcemanager.projects.get \
  --stage=GA
```

**Note**: If the role already exists, you can skip this step or update it using `gcloud iam roles update`.

### 5. Grant KMS Permissions
Assign the necessary roles to the service account. Each role requires a separate command:

```sh
# Custom key creator role
gcloud projects add-iam-policy-binding <PROJECT_ID> \
  --member="serviceAccount:ucan-kms-sa@<PROJECT_ID>.iam.gserviceaccount.com" \
  --role="projects/<PROJECT_ID>/roles/kmsKeyCreator"

# Encrypt/Decrypt permissions
gcloud projects add-iam-policy-binding <PROJECT_ID> \
  --member="serviceAccount:ucan-kms-sa@<PROJECT_ID>.iam.gserviceaccount.com" \
  --role="roles/cloudkms.cryptoKeyEncrypterDecrypter"

# Public key viewer permissions
gcloud projects add-iam-policy-binding <PROJECT_ID> \
  --member="serviceAccount:ucan-kms-sa@<PROJECT_ID>.iam.gserviceaccount.com" \
  --role="roles/cloudkms.publicKeyViewer"
```

### 6. Create KMS Key Ring

```sh
gcloud kms keyrings create ucan-kms-<ENVIRONMENT>-keyring --location=global
```

Replace `<ENVIRONMENT>` with your environment name (e.g., `staging`, `production`).

### 7. Allow Service Account Impersonation (Development Only)

Service Account impersonation is useful for local development, allowing you to generate short-lived access tokens without storing service account key files:

```sh
gcloud iam service-accounts add-iam-policy-binding \
  ucan-kms-sa@<PROJECT_ID>.iam.gserviceaccount.com \
  --member="user:<YOUR_USERNAME>@storacha.network" \
  --role="roles/iam.serviceAccountTokenCreator"
```

### 8. Generate Access Token (Development Only)

Generate a 1-hour access token for development:

```sh
gcloud auth print-access-token --impersonate-service-account=ucan-kms-sa@<PROJECT_ID>.iam.gserviceaccount.com
```

**⚠️ Security Note**: This token expires in 1 hour and should only be used for development. For production, use service account JSON keys until other access control method is implemented.

## Cloudflare Worker Configuration

### 1. Create KV Namespace for Rate Limiting

The KV namespace stores rate limiting data for the KMS service:

```sh
npx wrangler kv namespace create KMS-RATE-LIMIT_KV -e <ENVIRONMENT_NAME>
```

After creation, add the returned KV namespace ID to the appropriate environment section in `wrangler.toml`.

### 2. Set Environment Secrets

#### KMS Principal Key

This is the main signing key for UCAN operations:

```sh
npx wrangler secret put UCAN_KMS_PRINCIPAL_KEY -e <ENVIRONMENT_NAME>
```

#### Google KMS Authentication

**For Development (using access tokens):**

```sh
npx wrangler secret put GOOGLE_KMS_TOKEN -e <ENVIRONMENT_NAME>
```

Use the access token generated in step 8 of the Google Cloud setup.

**For Production/Staging (using service account JSON):**

First, create and download a service account key:

```sh
gcloud iam service-accounts keys create ucan-kms-sa-key.json \
  --iam-account=ucan-kms-sa@<PROJECT_ID>.iam.gserviceaccount.com
```

Then set the secret:

```sh
npx wrangler secret put GOOGLE_KMS_SERVICE_ACCOUNT_JSON -e <ENVIRONMENT_NAME>
```

Paste the entire JSON content when prompted.

**⚠️ Security**: Delete the local JSON file after uploading and rotate keys regularly.

### 3. Deploy

```sh
npx wrangler deploy -e <ENVIRONMENT_NAME>
```

## Validation

### Verify Google Cloud Setup

1. **Check service account creation:**

   ```sh
   gcloud iam service-accounts describe ucan-kms-sa@<PROJECT_ID>.iam.gserviceaccount.com
   ```

2. **Verify IAM bindings:**

   ```sh
   gcloud projects get-iam-policy <PROJECT_ID> \
     --flatten="bindings[].members" \
     --filter="bindings.members:ucan-kms-sa@<PROJECT_ID>.iam.gserviceaccount.com"
   ```

3. **Check keyring creation:**

   ```sh
   gcloud kms keyrings list --location=global
   ```

### Test Worker Deployment

1. Check the worker is accessible at your Cloudflare Workers URL
2. Verify the worker can authenticate with Google KMS
3. Test basic KMS operations (key creation, encryption/decryption)

## Troubleshooting

### Common Issues

**"Role already exists" error:**

- Skip the role creation step or use `gcloud iam roles update` instead

**"Permission denied" errors:**

- Verify you have the necessary permissions in the Google Cloud project
- Check that your `gcloud` CLI is authenticated with the correct account

**Worker deployment fails:**

- Ensure all required secrets are set
- Verify the KV namespace ID is correctly configured in `wrangler.toml`
- Check that the service account has the necessary permissions

**KMS operations fail:**

- Verify the keyring exists and is accessible
- Check that the service account has the correct IAM roles
- For development, ensure your access token hasn't expired (1-hour limit)

### Getting Help

- Check Google Cloud Console for detailed error messages
- Use `gcloud auth list` to verify authentication
- Run `npx wrangler tail -e <ENVIRONMENT_NAME>` to see real-time worker logs

## Security Best Practices

1. **Principle of Least Privilege**: The custom `kmsKeyCreator` role provides minimal necessary permissions
2. **Environment Separation**: Use separate projects/environments for staging and production
3. **Audit Logging**: Monitor KMS operations through Google Cloud audit logs
4. **Access Reviews**: Regularly review who has access to service accounts and KMS resources