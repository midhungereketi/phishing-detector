const lessons = [
  ['01', 'Read the real hostname', 'https://bank.example.attacker.test/login belongs to attacker.test, not bank.example. Words in the path do not identify the organization. Content before @ is user information; the destination follows it.'],
  ['02', 'HTTPS is only one clue', 'HTTPS protects data in transit. A phishing site can also use HTTPS. Check the destination and the reason you were asked to visit before entering sensitive information.'],
  ['03', 'Inspect unexpected email', 'Check From and Reply-To, the actual link destination, and suspicious attachments. Urgent requests for passwords, OTPs or payments deserve independent verification through a known channel.'],
  ['04', 'Understand email authentication', 'SPF checks sending-server authorization, DKIM checks a message signature, and DMARC checks alignment with the From domain. Pasted header text cannot establish that these checks really passed.'],
  ['05', 'Know what the ML model sees', 'The URL classifier uses lexical features such as hostname length, subdomains and numeric characters. The email classifier uses TF-IDF text and structural metadata. Both can produce false positives and miss new attacks.'],
  ['06', 'Respond to a suspicious message', 'Avoid its links and attachments. Open the service using a known bookmark and verify the request. If you already shared credentials, change them through the official site and notify the responsible administrator.'],
];
export default function Academy() {
  return <><div className="page-heading"><div><div className="eyebrow">THE HUMAN LAYER</div><h1>A little awareness goes far<span className="heading-dot">.</span></h1><p>Six concepts to help you interpret a scan and explain the project.</p></div></div><div className="lesson-grid">{lessons.map(([number, title, text]) => <article className="card lesson" key={number}><span className="number-marker">{number}</span><h2>{title}</h2><p>{text}</p></article>)}</div></>;
}
