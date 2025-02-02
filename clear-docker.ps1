$containers = docker container ls -aq; if ($containers) { docker container stop $containers 2>$null; docker container rm -f $containers 2>$null }
$images = docker image ls -aq; if ($images) { docker image rm -f $images 2>$null }
$volumes = docker volume ls -q; if ($volumes) { docker volume rm $volumes 2>$null }
$networks = docker network ls --format "{{.ID}} {{.Name}}" | ForEach-Object { $parts = $_.Split(" "); if ($parts[1] -notin @("bridge","host","none")) { $parts[0] } }
if ($networks) { docker network rm $networks 2>$null }
docker builder prune -af
$secrets = docker secret ls -q; if ($secrets) { docker secret rm $secrets 2>$null }
$configs = docker config ls -q; if ($configs) { docker config rm $configs 2>$null }
$plugins = docker plugin ls -q; if ($plugins) { docker plugin rm -f $plugins 2>$null }
$contexts = docker context ls --format "{{.Name}}"; foreach ($context in $contexts) { if ($context -ne "default" -and $context -ne "docker-desktop") { docker context rm $context 2>$null } }
