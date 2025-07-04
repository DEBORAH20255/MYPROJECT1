export default function handler(req, res) {
  if (req.method === "POST") {
    const { email, password, provider } = req.body;
    // Dummy logic for demonstration, replace with real authentication
    if (
      email &&
      password &&
      ["aol", "office365", "yahoo", "outlook", "others"].includes(provider)
    ) {
      res.status(200).json({ success: true, session: "dummy-session-token" });
    } else {
      res.status(401).json({ success: false });
    }
  } else {
    res.status(405).json({ success: false, message: "Method not allowed" });
  }
}