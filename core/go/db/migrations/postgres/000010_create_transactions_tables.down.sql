BEGIN;
DROP TABLE IF EXISTS transaction_deps;
DROP TABLE IF EXISTS transaction_status;
DROP TABLE IF EXISTS transaction_receipts;
DROP TABLE IF EXISTS transactions;
DROP TABLE IF EXISTS abi_errors;
DROP TABLE IF EXISTS abis;
COMMIT;
