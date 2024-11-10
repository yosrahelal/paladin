BEGIN;
DROP TABLE prepared_txn_states;
DROP TABLE prepared_txns;
DROP TABLE prepared_txn_distribution_acknowledgments;
DROP TABLE prepared_txn_distributions;
COMMIT;