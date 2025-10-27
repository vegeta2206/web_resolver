<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Résultats DNS (Double vue)</title>
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
        <h2>Résolution DNS avec Détection de Double Vue</h2>

        <?php
        if ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($_POST['host'])) {
            echo "<p>Aucun hôte spécifié.</p>";
            exit;
        }

        $host_raw = trim($_POST['host']);
        $host = escapeshellarg($host_raw);

        $config = json_decode(file_get_contents('config.json'), true);

        function resolve_dns($host, $servers, $query_type) {
            $results = [];
            foreach ($servers as $server) {
                $start_time = microtime(true);
                
                // Construction de la commande dig avec le bon type de requête
                if ($query_type === 'PTR') {
                    $cmd = "dig @$server +timeout=2 +tries=1 +nocmd -x $host";
                } else {
                    $cmd = "dig @$server +timeout=2 +tries=1 +nocmd $query_type $host";
                }
                $output = shell_exec($cmd);
                $duration = round((microtime(true) - $start_time) * 1000, 2); // en ms

                // Extraction du statut DNS
                preg_match('/status: (\w+),/', $output, $status_match);
                $status = $status_match[1] ?? 'UNKNOWN';

                // Extraction des enregistrements selon le type
                $records = [];
                if ($query_type === 'PTR') {
                    // Pour les requêtes PTR (reverse DNS) - chercher dans la section ANSWER
                    preg_match_all('/^\s*\S+\s+\d+\s+IN\s+PTR\s+([^\s]+)\.?$/m', $output, $matches);
                    $records = $matches[1] ?? [];
                } else if ($query_type === 'A') {
                    // Pour les requêtes A (IPv4)
                    preg_match_all('/\sA\s+([\d\.]+)/', $output, $matches);
                    $records = $matches[1] ?? [];
                } else if ($query_type === 'AAAA') {
                    // Pour les requêtes AAAA (IPv6)
                    preg_match_all('/\sAAAA\s+([a-f0-9:]+)/i', $output, $matches);
                    $records = $matches[1] ?? [];
                }

                // Nettoyage de la sortie : suppression des lignes de commentaires et lignes vides
                $lines = explode("\n", trim($output));
                $clean_lines = [];
                foreach ($lines as $line) {
                    $line = trim($line);
                    // Garder seulement les lignes utiles (pas de commentaires ni de lignes vides)
                    if (!empty($line) && !str_starts_with($line, ';') && !str_starts_with($line, '<<>>')) {
                        $clean_lines[] = $line;
                    }
                }
                
                // Création d'un affichage synthétique
                $display_output = '';
                if ($status === 'NOERROR' && !empty($records)) {
                    // Affichage synthétique des enregistrements trouvés
                    $display_output = implode(', ', $records);
                } else {
                    // Affichage du statut pour les erreurs
                    $display_output = "Status: $status";
                    if (!empty($clean_lines)) {
                        $display_output .= "\n" . implode("\n", $clean_lines);
                    }
                }

                $results[$server] = [
                    'raw' => $display_output,
                    'status' => $status,
                    'records' => $records,
                    'time' => $duration
                ];
            }
            return $results;
        }

        // Détection du type de requête selon l'entrée
        if (filter_var($host_raw, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $query_type = 'PTR';
            $host_for_query = $host_raw; // Garder l'IP originale pour -x
            $host = escapeshellarg($host_for_query);
        } else if (filter_var($host_raw, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $query_type = 'PTR';
            $host_for_query = $host_raw; // Garder l'IP originale pour -x
            $host = escapeshellarg($host_for_query);
        } else {
            // Pour les noms de domaine, on fait à la fois A et AAAA
            $query_type = 'A+AAAA';
        }

        if ($query_type === 'A+AAAA') {
            // Résolution A et AAAA pour les noms de domaine
            $dns_publics_a = resolve_dns($host, $config['dns_publics'], 'A');
            $dns_prives_a = resolve_dns($host, $config['dns_prives'], 'A');
            $dns_publics_aaaa = resolve_dns($host, $config['dns_publics'], 'AAAA');
            $dns_prives_aaaa = resolve_dns($host, $config['dns_prives'], 'AAAA');
            
            // Fusion des résultats A et AAAA
            $dns_publics = [];
            $dns_prives = [];
            
            foreach ($dns_publics_a as $server => $data_a) {
                $data_aaaa = $dns_prives_aaaa[$server] ?? ['records' => [], 'status' => 'UNKNOWN'];
                $dns_publics[$server . ' (A)'] = $data_a;
                if (!empty($dns_publics_aaaa[$server]['records']) || $dns_publics_aaaa[$server]['status'] !== 'NXDOMAIN') {
                    $dns_publics[$server . ' (AAAA)'] = $dns_publics_aaaa[$server];
                }
            }
            
            foreach ($dns_prives_a as $server => $data_a) {
                $data_aaaa = $dns_prives_aaaa[$server] ?? ['records' => [], 'status' => 'UNKNOWN'];
                $dns_prives[$server . ' (A)'] = $data_a;
                if (!empty($dns_prives_aaaa[$server]['records']) || $dns_prives_aaaa[$server]['status'] !== 'NXDOMAIN') {
                    $dns_prives[$server . ' (AAAA)'] = $dns_prives_aaaa[$server];
                }
            }
        } else {
            // Résolution PTR pour les adresses IP
            $dns_publics = resolve_dns($host, $config['dns_publics'], $query_type);
            $dns_prives = resolve_dns($host, $config['dns_prives'], $query_type);
        }

        // Comparaison des résultats pour détecter la vraie double vue DNS
        // Double vue = DNS publics retournent des IPs publiques, DNS privés retournent des IPs privées
        // pour le même enregistrement
        
        function is_private_ip($ip) {
            if (!filter_var($ip, FILTER_VALIDATE_IP)) return false;
            
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                // Plages IPv4 privées : 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE) === false;
            } else {
                // IPv6 privées : fc00::/7, fe80::/10, ::1/128
                $ip_bin = inet_pton($ip);
                if ($ip_bin === false) return false;
                
                // Vérifier les plages privées IPv6
                $first_byte = ord($ip_bin[0]);
                return ($first_byte >= 0xfc && $first_byte <= 0xfd) || // fc00::/7
                       ($first_byte == 0xfe && (ord($ip_bin[1]) & 0xc0) == 0x80) || // fe80::/10
                       ($ip === '::1'); // loopback
            }
        }
        
        // Collecte des IPs publiques et privées
        $public_ips = [];
        $private_ips = [];
        
        foreach ($dns_publics as $data) {
            if ($data['status'] === 'NOERROR') {
                foreach ($data['records'] as $ip) {
                    if (filter_var($ip, FILTER_VALIDATE_IP)) {
                        $public_ips[] = $ip;
                    }
                }
            }
        }
        
        foreach ($dns_prives as $data) {
            if ($data['status'] === 'NOERROR') {
                foreach ($data['records'] as $ip) {
                    if (filter_var($ip, FILTER_VALIDATE_IP)) {
                        $private_ips[] = $ip;
                    }
                }
            }
        }
        
        // Détection de double vue : 
        // - Les DNS publics retournent principalement des IPs publiques
        // - Les DNS privés retournent principalement des IPs privées
        // - ET il y a des IPs différentes entre les deux groupes
        
        $public_has_public_ips = false;
        $public_has_private_ips = false;
        $private_has_public_ips = false;
        $private_has_private_ips = false;
        
        foreach ($public_ips as $ip) {
            if (is_private_ip($ip)) {
                $public_has_private_ips = true;
            } else {
                $public_has_public_ips = true;
            }
        }
        
        foreach ($private_ips as $ip) {
            if (is_private_ip($ip)) {
                $private_has_private_ips = true;
            } else {
                $private_has_public_ips = true;
            }
        }
        
        // Double vue détectée si :
        // 1. DNS publics retournent des IPs publiques ET DNS privés retournent des IPs privées
        // 2. OU les ensembles d'IPs sont complètement différents
        $double_vue = false;
        
        if (!empty($public_ips) && !empty($private_ips)) {
            // Cas 1: Séparation public/privé claire
            if ($public_has_public_ips && !$public_has_private_ips && 
                $private_has_private_ips && !$private_has_public_ips) {
                $double_vue = true;
            }
            // Cas 2: IPs complètement différentes (pas de Round Robin)
            else {
                $public_unique = array_unique($public_ips);
                $private_unique = array_unique($private_ips);
                sort($public_unique);
                sort($private_unique);
                
                // Double vue si aucune IP en commun
                $common_ips = array_intersect($public_unique, $private_unique);
                if (empty($common_ips)) {
                    $double_vue = true;
                }
            }
        }
        
        // === ANALYSE POUR LE RAPPORT ===
        
        // 1. Support IPv4/IPv6
        $support_ipv4 = false;
        $support_ipv6 = false;
        $has_round_robin = false;
        $has_gslb = false;
        
        // Analyse des enregistrements pour détecter IPv4/IPv6
        foreach (array_merge($dns_publics, $dns_prives) as $data) {
            foreach ($data['records'] as $record) {
                if (filter_var($record, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                    $support_ipv4 = true;
                }
                if (filter_var($record, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                    $support_ipv6 = true;
                }
            }
        }
        
        // 2. Niveau de confiance (uniformité des réponses par type)
        $public_responses_a = [];
        $private_responses_a = [];
        $public_responses_aaaa = [];
        $private_responses_aaaa = [];
        
        foreach ($dns_publics as $server => $data) {
            if ($data['status'] === 'NOERROR') {
                // Séparer les réponses A et AAAA
                $a_records = [];
                $aaaa_records = [];
                
                foreach ($data['records'] as $record) {
                    if (filter_var($record, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                        $a_records[] = $record;
                    } elseif (filter_var($record, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                        $aaaa_records[] = $record;
                    }
                }
                
                if (!empty($a_records)) {
                    sort($a_records);
                    $public_responses_a[] = $a_records;
                }
                if (!empty($aaaa_records)) {
                    sort($aaaa_records);
                    $public_responses_aaaa[] = $aaaa_records;
                }
            }
        }
        
        foreach ($dns_prives as $server => $data) {
            if ($data['status'] === 'NOERROR') {
                // Séparer les réponses A et AAAA
                $a_records = [];
                $aaaa_records = [];
                
                foreach ($data['records'] as $record) {
                    if (filter_var($record, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                        $a_records[] = $record;
                    } elseif (filter_var($record, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                        $aaaa_records[] = $record;
                    }
                }
                
                if (!empty($a_records)) {
                    sort($a_records);
                    $private_responses_a[] = $a_records;
                }
                if (!empty($aaaa_records)) {
                    sort($aaaa_records);
                    $private_responses_aaaa[] = $aaaa_records;
                }
            }
        }
        
        // Calcul d'uniformité pour IPv4 (A)
        $public_unique_a = array_unique(array_map('serialize', $public_responses_a));
        $private_unique_a = array_unique(array_map('serialize', $private_responses_a));
        
        $confiance_publique_a = count($public_responses_a) > 0 ? (count($public_unique_a) == 1 ? 100 : 0) : 0;
        $confiance_privee_a = count($private_responses_a) > 0 ? (count($private_unique_a) == 1 ? 100 : 0) : 0;
        
        // Calcul d'uniformité pour IPv6 (AAAA)
        $public_unique_aaaa = array_unique(array_map('serialize', $public_responses_aaaa));
        $private_unique_aaaa = array_unique(array_map('serialize', $private_responses_aaaa));
        
        $confiance_publique_aaaa = count($public_responses_aaaa) > 0 ? (count($public_unique_aaaa) == 1 ? 100 : 0) : 0;
        $confiance_privee_aaaa = count($private_responses_aaaa) > 0 ? (count($private_unique_aaaa) == 1 ? 100 : 0) : 0;
        
        // 3. Détection Round Robin / GSLB (par serveur DNS individuel)
        foreach (array_merge($dns_publics, $dns_prives) as $server => $data) {
            if (count($data['records']) > 1) {
                $has_round_robin = true;
                // Si plus de 3 IPs ou IPs dans des plages différentes, probable GSLB
                if (count($data['records']) > 3) {
                    $has_gslb = true;
                } else {
                    // Vérification si les IPs sont dans des réseaux différents (heuristique simple)
                    $networks = [];
                    foreach ($data['records'] as $ip) {
                        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                            $parts = explode('.', $ip);
                            $networks[] = $parts[0] . '.' . $parts[1];
                        }
                    }
                    if (count(array_unique($networks)) > 1) {
                        $has_gslb = true;
                    }
                }
            }
        }
        
        // Si pas de Round Robin détecté sur un serveur individuel, 
        // vérifier si différents serveurs retournent des IPs différentes (pas un vrai Round Robin)
        if (!$has_round_robin) {
            // Comparer les réponses entre serveurs du même type (publics vs publics, privés vs privés)
            $all_public_ips = [];
            $all_private_ips = [];
            
            foreach ($dns_publics as $data) {
                if ($data['status'] === 'NOERROR' && !empty($data['records'])) {
                    foreach ($data['records'] as $ip) {
                        if (filter_var($ip, FILTER_VALIDATE_IP)) {
                            $all_public_ips[] = $ip;
                        }
                    }
                }
            }
            
            foreach ($dns_prives as $data) {
                if ($data['status'] === 'NOERROR' && !empty($data['records'])) {
                    foreach ($data['records'] as $ip) {
                        if (filter_var($ip, FILTER_VALIDATE_IP)) {
                            $all_private_ips[] = $ip;
                        }
                    }
                }
            }
            
            // Si différents serveurs publics retournent des IPs différentes, ce n'est PAS du Round Robin
            // mais plutôt une configuration différente entre serveurs DNS
            $unique_public_ips = array_unique($all_public_ips);
            $unique_private_ips = array_unique($all_private_ips);
            
            // Round Robin détecté seulement si un serveur individuel retourne plusieurs IPs
            // pas si différents serveurs retournent des IPs différentes
        }
        
        // 4. Statistiques générales
        $total_servers = count($config['dns_publics']) + count($config['dns_prives']);
        $successful_responses = 0;
        $avg_response_time = 0;
        $total_time = 0;
        $response_count = 0;
        
        foreach (array_merge($dns_publics, $dns_prives) as $data) {
            if ($data['status'] === 'NOERROR') {
                $successful_responses++;
            }
            $total_time += $data['time'];
            $response_count++;
        }
        
        $avg_response_time = $response_count > 0 ? round($total_time / $response_count, 2) : 0;
        $success_rate = $total_servers > 0 ? round(($successful_responses / $total_servers) * 100, 1) : 0;
        ?>

        <h3>Résultat <?= $query_type ?> pour : <?= htmlspecialchars($host_raw) ?></h3>

        <!-- RAPPORT DE SYNTHÈSE -->
        <div class="section report-summary">
            <h4>📊 Rapport de Synthèse</h4>
            
            <div class="report-grid">
                <div class="report-item">
                    <h5>🌐 Support IP</h5>
                    <div class="report-value">
                        <?php if ($support_ipv4): ?>
                            <span class="support-yes">✅ IPv4</span>
                        <?php else: ?>
                            <span class="support-no">❌ IPv4</span>
                        <?php endif; ?>
                        
                        <?php if ($support_ipv6): ?>
                            <span class="support-yes">✅ IPv6</span>
                        <?php else: ?>
                            <span class="support-no">❌ IPv6</span>
                        <?php endif; ?>
                    </div>
                </div>
                
                <div class="report-item">
                    <h5>🎯 Uniformité des Réponses</h5>
                    <div class="report-value">
                        <?php if ($support_ipv4): ?>
                            <?php 
                            $has_public_ipv4_responses = count($public_responses_a) > 0;
                            $has_private_ipv4_responses = count($private_responses_a) > 0;
                            ?>
                            <?php if ($has_public_ipv4_responses): ?>
                                <div>IPv4 Publics: <strong><?= round($confiance_publique_a, 1) ?>%</strong></div>
                            <?php endif; ?>
                            <?php if ($has_private_ipv4_responses): ?>
                                <div>IPv4 Privés: <strong><?= round($confiance_privee_a, 1) ?>%</strong></div>
                            <?php endif; ?>
                            <?php if (!$has_public_ipv4_responses && !$has_private_ipv4_responses): ?>
                                <div>IPv4: <strong>N/A</strong></div>
                            <?php endif; ?>
                        <?php endif; ?>
                        
                        <?php if ($support_ipv6): ?>
                            <?php 
                            $has_public_ipv6_responses = count($public_responses_aaaa) > 0;
                            $has_private_ipv6_responses = count($private_responses_aaaa) > 0;
                            ?>
                            <?php if ($has_public_ipv6_responses): ?>
                                <div>IPv6 Publics: <strong><?= round($confiance_publique_aaaa, 1) ?>%</strong></div>
                            <?php endif; ?>
                            <?php if ($has_private_ipv6_responses): ?>
                                <div>IPv6 Privés: <strong><?= round($confiance_privee_aaaa, 1) ?>%</strong></div>
                            <?php endif; ?>
                            <?php if (!$has_public_ipv6_responses && !$has_private_ipv6_responses): ?>
                                <div>IPv6: <strong>N/A</strong></div>
                            <?php endif; ?>
                        <?php endif; ?>
                        
                        <?php if (!$support_ipv4 && !$support_ipv6): ?>
                            <div><strong>N/A</strong> (Pas d'IP dans les réponses)</div>
                        <?php endif; ?>
                        <small>(Cohérence par type d'enregistrement)</small>
                    </div>
                </div>
                
                <div class="report-item">
                    <h5>⚖️ Load Balancing</h5>
                    <div class="report-value">
                        <?php if ($has_gslb): ?>
                            <span class="lb-detected">🌍 GSLB détecté</span>
                        <?php elseif ($has_round_robin): ?>
                            <span class="lb-detected">🔄 Round Robin détecté</span>
                        <?php else: ?>
                            <span class="lb-none">➡️ Aucun LB détecté</span>
                        <?php endif; ?>
                    </div>
                </div>
                
                <div class="report-item">
                    <h5>📈 Statistiques</h5>
                    <div class="report-value">
                        <div>Taux de succès: <strong><?= $success_rate ?>%</strong></div>
                        <div>Temps moyen: <strong><?= $avg_response_time ?> ms</strong></div>
                        <div>Serveurs testés: <strong><?= $total_servers ?></strong></div>
                    </div>
                </div>
                
                <div class="report-item">
                    <h5>🔍 Type de Requête</h5>
                    <div class="report-value">
                        <strong><?= $query_type ?></strong>
                        <?php if ($query_type === 'PTR'): ?>
                            <small>(Résolution inverse)</small>
                        <?php else: ?>
                            <small>(Résolution directe)</small>
                        <?php endif; ?>
                    </div>
                </div>
                
                <div class="report-item">
                    <h5>⚠️ Sécurité DNS</h5>
                    <div class="report-value">
                        <?php if ($double_vue): ?>
                            <span class="security-risk">🔴 Double vue DNS détectée</span>
                            <small>IPs publiques ≠ IPs privées</small>
                        <?php else: ?>
                            <span class="security-ok">🟢 Configuration cohérente</span>
                            <small>Aucune double vue détectée</small>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
            
            <?php if ($has_round_robin || $has_gslb): ?>
                <div class="report-note">
                    <strong>💡 Note:</strong> 
                    <?php if ($has_gslb): ?>
                        Un Global Server Load Balancing (GSLB) semble être configuré, indiquant une infrastructure distribuée géographiquement.
                    <?php else: ?>
                        Un Round Robin DNS est configuré pour répartir la charge entre plusieurs serveurs.
                    <?php endif; ?>
                </div>
            <?php endif; ?>
            
            <?php if ($double_vue): ?>
                <div class="report-warning">
                    <strong>⚠️ Attention:</strong> La double vue DNS détectée peut indiquer une configuration Split-DNS intentionnelle ou un problème de sécurité. Les utilisateurs internes et externes accèdent à des serveurs différents.
                </div>
            <?php endif; ?>
        </div>
                <br><br>

        <?php if ($double_vue): ?>
            <div class="alert">
                ⚠️ <strong>Double vue DNS détectée :</strong> les serveurs DNS publics et privés retournent des adresses IP différentes pour le même enregistrement.
                <?php if ($public_has_public_ips && $private_has_private_ips): ?>
                    <br><small>Les DNS publics retournent des IPs publiques, les DNS privés des IPs privées.</small>
                <?php else: ?>
                    <br><small>Les ensembles d'adresses IP retournés sont complètement différents.</small>
                <?php endif; ?>
            </div>
        <?php elseif ($has_round_robin): ?>
            <div class="alert info">
                ℹ️ <strong>Round Robin DNS détecté :</strong> plusieurs adresses IP sont retournées pour répartir la charge.
            </div>
        <?php else: ?>
            <div class="alert success">
                ✅ <strong>Configuration DNS cohérente :</strong> les serveurs DNS publics et privés retournent les mêmes adresses.
            </div>
        <?php endif; ?>
        <br><br>
        <div class="section">
            <h4>Résultats DNS</h4>
            <table class="dns-table">
                <thead>
                    <tr>
                        <th>Résolveur</th>
                        <th>Zone</th>
                        <th>A</th>
                        <th>Response time (A)</th>
                        <th>AAAA</th>
                        <th>Response time (AAAA)</th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                    // Collecte de tous les serveurs uniques
                    $all_servers = array_unique(array_merge($config['dns_publics'], $config['dns_prives']));
                    
                    // Collecte des temps de réponse pour déterminer fastest/slowest
                    $a_times = [];
                    $aaaa_times = [];
                    
                    foreach ($all_servers as $server) {
                        // Récupération des données A
                        $a_key = $server . ' (A)';
                        $a_data = isset($dns_publics[$a_key]) ? $dns_publics[$a_key] : (isset($dns_prives[$a_key]) ? $dns_prives[$a_key] : null);
                        
                        // Récupération des données AAAA
                        $aaaa_key = $server . ' (AAAA)';
                        $aaaa_data = isset($dns_publics[$aaaa_key]) ? $dns_publics[$aaaa_key] : (isset($dns_prives[$aaaa_key]) ? $dns_prives[$aaaa_key] : null);
                        
                        // Pour PTR, utiliser les données directes
                        if ($query_type === 'PTR') {
                            $ptr_data = isset($dns_publics[$server]) ? $dns_publics[$server] : (isset($dns_prives[$server]) ? $dns_prives[$server] : null);
                            $a_data = $ptr_data;
                            $aaaa_data = null; // Pas de AAAA pour PTR
                        }
                        
                        // Collecte des temps valides
                        if ($a_data && $a_data['status'] === 'NOERROR') {
                            $a_times[$server] = $a_data['time'];
                        }
                        if ($aaaa_data && $aaaa_data['status'] === 'NOERROR') {
                            $aaaa_times[$server] = $aaaa_data['time'];
                        }
                    }
                    
                    // Détermination des fastest/slowest
                    $a_fastest = !empty($a_times) ? min($a_times) : null;
                    $a_slowest = !empty($a_times) ? max($a_times) : null;
                    $aaaa_fastest = !empty($aaaa_times) ? min($aaaa_times) : null;
                    $aaaa_slowest = !empty($aaaa_times) ? max($aaaa_times) : null;
                    
                    // Affichage du tableau
                    foreach ($all_servers as $server) {
                        $zone = in_array($server, $config['dns_publics']) ? 'Public' : 'Privé';
                        
                        // Récupération des données A
                        $a_key = $server . ' (A)';
                        $a_data = isset($dns_publics[$a_key]) ? $dns_publics[$a_key] : (isset($dns_prives[$a_key]) ? $dns_prives[$a_key] : null);
                        
                        // Récupération des données AAAA
                        $aaaa_key = $server . ' (AAAA)';
                        $aaaa_data = isset($dns_publics[$aaaa_key]) ? $dns_publics[$aaaa_key] : (isset($dns_prives[$aaaa_key]) ? $dns_prives[$aaaa_key] : null);
                        
                        // Pour PTR, utiliser les données directes
                        if ($query_type === 'PTR') {
                            $ptr_data = isset($dns_publics[$server]) ? $dns_publics[$server] : (isset($dns_prives[$server]) ? $dns_prives[$server] : null);
                            $a_data = $ptr_data;
                            $aaaa_data = null; // Pas de AAAA pour PTR
                        }
                        
                        // Affichage des résultats A
                        $a_result = '';
                        $a_time = '';
                        if ($a_data) {
                            if ($a_data['status'] === 'NOERROR' && !empty($a_data['records'])) {
                                $a_result = '<span class="success-result">✅ ' . implode(', ', $a_data['records']) . '</span>';
                            } else {
                                $a_result = '<span class="error-result">❌ ' . $a_data['status'] . '</span>';
                            }
                            $a_time_display = $a_data['time'] . ' ms';
                            if ($a_data['time'] == $a_fastest && $a_fastest !== null) {
                                $a_time_display .= ' <span class="fastest">🚀 fastest</span>';
                            } elseif ($a_data['time'] == $a_slowest && $a_slowest !== null) {
                                $a_time_display .= ' <span class="slowest">🐌 slowest</span>';
                            }
                            $a_time = $a_time_display;
                        }
                        
                        // Affichage des résultats AAAA
                        $aaaa_result = '';
                        $aaaa_time = '';
                        if ($aaaa_data) {
                            if ($aaaa_data['status'] === 'NOERROR' && !empty($aaaa_data['records'])) {
                                $aaaa_result = '<span class="success-result">✅ ' . implode(', ', $aaaa_data['records']) . '</span>';
                            } else {
                                $aaaa_result = '<span class="error-result">❌ ' . $aaaa_data['status'] . '</span>';
                            }
                            $aaaa_time_display = $aaaa_data['time'] . ' ms';
                            if ($aaaa_data['time'] == $aaaa_fastest && $aaaa_fastest !== null) {
                                $aaaa_time_display .= ' <span class="fastest">🚀 fastest</span>';
                            } elseif ($aaaa_data['time'] == $aaaa_slowest && $aaaa_slowest !== null) {
                                $aaaa_time_display .= ' <span class="slowest">🐌 slowest</span>';
                            }
                            $aaaa_time = $aaaa_time_display;
                        } elseif ($query_type === 'PTR') {
                            $aaaa_result = '<span class="na">N/A</span>';
                            $aaaa_time = '<span class="na">N/A</span>';
                        }
                        
                        echo "<tr>
                            <td>{$server}</td>
                            <td>{$zone}</td>
                            <td>{$a_result}</td>
                            <td>{$a_time}</td>
                            <td>{$aaaa_result}</td>
                            <td>{$aaaa_time}</td>
                        </tr>";
                    }
                    ?>
                </tbody>
            </table>
        </div>

        <a href="index.php">↩️ Nouvelle requête</a>
    </div>

    <footer>
        <div class="footer-content">
            <p>&copy; 2025 vegeta2206. Tous droits réservés.</p>
        </div>
    </footer>
</body>
</html>
