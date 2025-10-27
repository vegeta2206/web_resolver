<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Résolution DNS double-vue</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <header>
        <div class="header-content">
            <img src="img/orange-logo.svg" alt="Orange Logo" class="logo">
            <h1>Web Resolver</h1>
        </div>
    </header>

    <div class="container">
        <h2>Détection de double vue DNS</h2>
        <form method="POST" action="resolve.php">
            <input type="text" name="host" placeholder="Nom de domaine ou IP" required>
            <button type="submit">Résoudre</button>
        </form>
    </div>

    <footer>
        <div class="footer-content">
            <p>&copy; 2025 vegeta2206. Tous droits réservés.</p>
        </div>
    </footer>
</body>
</html>

