export function analyzeURL(inputURL) {
  let score = 0;
  let reasons = [];

  const url = inputURL.toLowerCase();

  if (!url.startsWith("https://")) {
    score += 20;
    reasons.push("URL is not using HTTPS");
  }

  const suspiciousWords = [
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "bank",
    "payment",
    "free",
  ];

  suspiciousWords.forEach((word) => {
    if (url.includes(word)) {
      score += 15;
      reasons.push(`Contains suspicious keyword: ${word}`);
    }
  });

  if (url.length > 60) {
    score += 10;
    reasons.push("URL is unusually long");
  }

  if (url.includes("@")) {
    score += 20;
    reasons.push("URL contains '@' symbol");
  }

  const dotCount = (url.match(/\./g) || []).length;
  if (dotCount > 3) {
    score += 15;
    reasons.push("URL has too many subdomains");
  }

  const ipPattern = /(\d{1,3}\.){3}\d{1,3}/;
  if (ipPattern.test(url)) {
    score += 25;
    reasons.push("URL uses IP address instead of domain");
  }

  let riskLevel = "Low";
  if (score > 30 && score <= 60) riskLevel = "Medium";
  if (score > 60) riskLevel = "High";

  return {
    score,
    riskLevel,
    reasons,
  };
}