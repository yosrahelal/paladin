BEGIN;

-- Generate an identity column for the public_txns table
ALTER TABLE public_txns ADD "pub_txn_id" BIGINT GENERATED ALWAYS AS IDENTITY;

-- And add the foreign relationship to the other tables as an empty column
ALTER TABLE public_submissions ADD "pub_txn_id" BIGINT;
CREATE UNIQUE INDEX public_submissions_pub_txn_id on public_submissions("pub_txn_id");
ALTER TABLE public_completions ADD "pub_txn_id" BIGINT;
CREATE UNIQUE INDEX public_completions_pub_txn_id on public_completions("pub_txn_id");
ALTER TABLE public_txn_bindings ADD "pub_txn_id" BIGINT;
CREATE UNIQUE INDEX public_txn_bindings_pub_txn_id on public_txn_bindings("pub_txn_id");

-- Add new new reference column to the public_submissions
UPDATE public_submissions
SET "pub_txn_id" = updates."pub_txn_id"
FROM ( SELECT "signer_nonce", "pub_txn_id" FROM public_txns ) AS updates
WHERE ( public_submissions."signer_nonce" = updates."signer_nonce" );

-- Add new new reference column to the public_completions
UPDATE public_completions
SET "pub_txn_id" = updates."pub_txn_id"
FROM ( SELECT "signer_nonce", "pub_txn_id" FROM public_txns ) AS updates
WHERE ( public_completions."signer_nonce" = updates."signer_nonce" );

-- Add new new reference column to the public_txn_bindings
UPDATE public_txn_bindings
SET "pub_txn_id" = updates."pub_txn_id"
FROM ( SELECT "signer_nonce", "pub_txn_id" FROM public_txns ) AS updates
WHERE ( public_txn_bindings."signer_nonce" = updates."signer_nonce" );

-- Drop the old references
ALTER TABLE public_submissions DROP CONSTRAINT public_submissions_signer_nonce_fkey;
ALTER TABLE public_completions DROP CONSTRAINT public_completions_signer_nonce_fkey;
ALTER TABLE public_txn_bindings DROP CONSTRAINT public_txn_bindings_signer_nonce_fkey;
ALTER TABLE public_submissions DROP COLUMN "signer_nonce";
ALTER TABLE public_completions DROP COLUMN "signer_nonce";
ALTER TABLE public_txn_bindings DROP COLUMN "signer_nonce";
ALTER TABLE public_txns DROP COLUMN "signer_nonce";

-- Make the new column the primary key
ALTER TABLE public_txns ADD CONSTRAINT public_txns_pkey PRIMARY KEY ("pub_txn_id");

-- Update the submissions/completions tables to lock in the new reference
ALTER TABLE public_submissions ALTER COLUMN "pub_txn_id" SET NOT NULL;
ALTER TABLE public_submissions ADD CONSTRAINT public_submissions_pub_txn_id_fkey FOREIGN KEY ("pub_txn_id") REFERENCES public_txns ("pub_txn_id") ON DELETE CASCADE;
ALTER TABLE public_completions ALTER COLUMN "pub_txn_id" SET NOT NULL;
ALTER TABLE public_completions ADD CONSTRAINT public_completions_pub_txn_id_fkey FOREIGN KEY ("pub_txn_id") REFERENCES public_txns ("pub_txn_id") ON DELETE CASCADE;
ALTER TABLE public_txn_bindings ALTER COLUMN "pub_txn_id" SET NOT NULL;
ALTER TABLE public_txn_bindings ADD CONSTRAINT public_txn_bindings_pub_txn_id_fkey FOREIGN KEY ("pub_txn_id") REFERENCES public_txns ("pub_txn_id") ON DELETE CASCADE;

-- Now we can make the nonce optional on the public_txns
ALTER TABLE public_txns ALTER COLUMN "nonce" DROP NOT NULL;

-- We also need to update the dispatches table
ALTER TABLE dispatches ADD "public_transaction_id" BIGINT;
UPDATE dispatches
SET "public_transaction_id" = updates."pub_txn_id"
FROM ( SELECT "nonce", "from", "pub_txn_id" FROM public_txns ) AS updates
WHERE dispatches."public_transaction_address" = updates."from" AND dispatches."public_transaction_nonce" = updates."nonce";
DROP INDEX dispatches_public_private;
ALTER TABLE dispatches DROP COLUMN "public_transaction_nonce";
ALTER TABLE dispatches ALTER COLUMN "public_transaction_id" SET NOT NULL;
CREATE UNIQUE INDEX dispatches_public_private ON dispatches("public_transaction_address","public_transaction_id","private_transaction_id");

COMMIT;