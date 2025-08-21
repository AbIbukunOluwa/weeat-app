<!DOCTYPE html>
<html>
<head>
  <title><%= title %></title>
</head>
<body>
  <h1>Submit a Complaint</h1>
  <form method="POST" action="/complaint">
    <label>Order ID: <input type="text" name="orderId" required></label><br>
    <label>Description:<br>
      <textarea name="description" required></textarea>
    </label><br>
    <label>Attach Photo (url for now): <input type="text" name="photo"></label><br>
    <button type="submit">Submit</button>
  </form>
</body>
</html>
