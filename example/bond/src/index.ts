import PaladinClient from "paladin-sdk";

async function main() {
  const paladin = new PaladinClient({
    url: "http://127.0.0.1:31548",
  });

  const transactions = await paladin.queryTransactions({ limit: 1 });
  if (transactions.length > 0) {
    console.log("Transactions found");
  } else {
    console.log("No transactions found");
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error(err);
  });
}
