
function Initialize-TTWordList {
    [CmdletBinding()]
    param(
        [string]$Path = 'C:\TechToolbox\Config\wordlist.txt',
        [switch]$NoAmbiguous
    )

    # Curated starter list (add to this as you like)
    $words = @'
river
stone
blue
green
tiger
forest
echo
delta
nova
ember
maple
cedar
birch
pine
spruce
willow
aspen
elm
fir
hemlock
oak
silver
shadow
crimson
cobalt
onyx
raven
falcon
otter
fox
wolf
lynx
badger
eagle
harbor
summit
meadow
prairie
canyon
valley
spring
autumn
winter
summer
breeze
cloud
storm
thunder
rain
snow
frost
glacier
aurora
comet
meteor
orbit
quartz
granite
basalt
pebble
coral
reef
tide
lagoon
moss
fern
copper
iron
nickel
zinc
amber
topaz
agate
jade
opal
pearl
sapphire
ruby
garnet
swift
brisk
rapid
steady
bold
bright
quiet
gentle
keen
vivid
lively
nimble
solid
lofty
noble
true
prime
vantage
zenith
apex
vertex
vector
gamma
omega
alpha
sigma
photon
quark
ion
pixel
matrix
cipher
beacon
signal
kernel
crypto
evergreen
lake
riverbank
brook
cove
grove
ridge
peak
hollow
dawn
dusk
ember
flare
spark
glow
blaze
shade
marble
slate
shale
granule
opaline
auric
argent
bronze
brass
steel
carbon
graphite
neon
argon
radon
xenon
sonic
echoes
north
south
east
west
midway
frontier
praxis
nimbus
cirrus
stratus
cumulus
zephyr
current
eddy
vortex
ripple
cascade
deltaic
arbor
thicket
bramble
meander
vernal
solstice
equinox
tundra
taiga
sierra
mesa
butte
cairn
grottos
harvest
emberly
solace
tranquil
serene
poise
steadfast
anchor
keystone
waypoint
signal
beacon
lumen
prism
spectra
radian
vector
scalar
tensor
axial
normal
median
summitry
'@ -split "`n"

    $clean = $words |
    ForEach-Object { $_.Trim().ToLowerInvariant() } |
    Where-Object { $_ -match '^[a-z]{3,10}$' } |
    Select-Object -Unique

    if ($NoAmbiguous) {
        $clean = $clean | Where-Object { $_ -notmatch '[ilo]' }
    }

    $clean | Sort-Object | Set-Content -LiteralPath $Path -Encoding UTF8
    Write-Log -Level OK -Message "Word list written: $Path (`$NoAmbiguous=$NoAmbiguous)"
}

# SIG # Begin signature block
# MIIIngYJKoZIhvcNAQcCoIIIjzCCCIsCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAqUkSG96jA+Ub5
# MGBFgsvxWvOR0eO+4Qp5HcKh8SY1OKCCBRAwggUMMIIC9KADAgECAhAR+U4xG7FH
# qkyqS9NIt7l5MA0GCSqGSIb3DQEBCwUAMB4xHDAaBgNVBAMME1ZBRFRFSyBDb2Rl
# IFNpZ25pbmcwHhcNMjUxMjE5MTk1NDIxWhcNMjYxMjE5MjAwNDIxWjAeMRwwGgYD
# VQQDDBNWQURURUsgQ29kZSBTaWduaW5nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEA3pzzZIUEY92GDldMWuzvbLeivHOuMupgpwbezoG5v90KeuN03S5d
# nM/eom/PcIz08+fGZF04ueuCS6b48q1qFnylwg/C/TkcVRo0WFcKoFGT8yGxdfXi
# caHtapZfbSRh73r7qR7w0CioVveNBVgfMsTgE0WKcuwxemvIe/ptmkfzwAiw/IAC
# Ib0E0BjiX4PySbwWy/QKy/qMXYY19xpRItVTKNBtXzADUtzPzUcFqJU83vM2gZFs
# Or0MhPvM7xEVkOWZFBAWAubbMCJ3rmwyVv9keVDJChhCeLSz2XR11VGDOEA2OO90
# Y30WfY9aOI2sCfQcKMeJ9ypkHl0xORdhUwZ3Wz48d3yJDXGkduPm2vl05RvnA4T6
# 29HVZTmMdvP2475/8nLxCte9IB7TobAOGl6P1NuwplAMKM8qyZh62Br23vcx1fXZ
# TJlKCxBFx1nTa6VlIJk+UbM4ZPm954peB/fIqEacm8LkZ0cPwmLE5ckW7hfK4Trs
# o+RaudU1sKeA+FvpOWgsPccVRWcEYyGkwbyTB3xrIBXA+YckbANZ0XL7fv7x29hn
# gXbZipGu3DnTISiFB43V4MhNDKZYfbWdxze0SwLe8KzIaKnwlwRgvXDMwXgk99Mi
# EbYa3DvA/5ZWikLW9PxBFD7Vdr8ZiG/tRC9I2Y6fnb+PVoZKc/2xsW0CAwEAAaNG
# MEQwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQW
# BBRfYLVE8caSc990rnrIHUjoB7X/KjANBgkqhkiG9w0BAQsFAAOCAgEAiGB2Wmk3
# QBtd1LcynmxHzmu+X4Y5DIpMMNC2ahsqZtPUVcGqmb5IFbVuAdQphL6PSrDjaAR8
# 1S8uTfUnMa119LmIb7di7TlH2F5K3530h5x8JMj5EErl0xmZyJtSg7BTiBA/UrMz
# 6WCf8wWIG2/4NbV6aAyFwIojfAcKoO8ng44Dal/oLGzLO3FDE5AWhcda/FbqVjSJ
# 1zMfiW8odd4LgbmoyEI024KkwOkkPyJQ2Ugn6HMqlFLazAmBBpyS7wxdaAGrl18n
# 6bS7QuAwCd9hitdMMitG8YyWL6tKeRSbuTP5E+ASbu0Ga8/fxRO5ZSQhO6/5ro1j
# PGe1/Kr49Uyuf9VSCZdNIZAyjjeVAoxmV0IfxQLKz6VOG0kGDYkFGskvllIpQbQg
# WLuPLJxoskJsoJllk7MjZJwrpr08+3FQnLkRuisjDOc3l4VxFUsUe4fnJhMUONXT
# Sk7vdspgxirNbLmXU4yYWdsizz3nMUR0zebUW29A+HYme16hzrMPOeyoQjy4I5XX
# 3wXAFdworfPEr/ozDFrdXKgbLwZopymKbBwv6wtT7+1zVhJXr+jGVQ1TWr6R+8ea
# tIOFnY7HqGaxe5XB7HzOwJKdj+bpHAfXft1vUoiKr16VajLigcYCG8MdwC3sngO3
# JDyv2V+YMfsYBmItMGBwvizlQ6557NbK95ExggLkMIIC4AIBATAyMB4xHDAaBgNV
# BAMME1ZBRFRFSyBDb2RlIFNpZ25pbmcCEBH5TjEbsUeqTKpL00i3uXkwDQYJYIZI
# AWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0B
# CQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAv
# BgkqhkiG9w0BCQQxIgQgUt+9rWVATD0ZYPQyTu3MMDBe7SCRcrh7PNHhgskZl3ww
# DQYJKoZIhvcNAQEBBQAEggIAwcaG2iUstQduRZKtFM1coujXpWqwc3SzDlRbe2zR
# O+8enYJ7j+0wobzbjpj7WIiYgZOPzM0vih7Ghk3s/vprD9ZXqkGFAVXN+zxWytwm
# /yvZLClRVnMHldE3pJjQY3mdTD8kBQnHehY1u21GsEZPYm8QSnCdSJwUE9SXXaWx
# 9PAtqOm3YU1S2AdgwxpSdk/e34MhJg45SPgqONbk/xkushmdLAIZc+/EJTYVYVFF
# C7bXKX24INTC+VVyiiCuMnLyKZc+jbj5nO06FCWlGIPMWxfXIQT1U9EW3ficGYuw
# SwACH/ZTYkwgtKc/nGeGVuz7IGxm3RuGIAFux8Tp/909MVpPq7JnVvw9E+VgZ0De
# RLJNZZ27lUadg65RMw2f598po9EUG2xU238ddqcLhzOqnB203Q0cWXbPpR1tES5e
# jyYmqY17gZyyKf+aJH21CMx6x2tZLPpZBZO1XBCopgNg2hpjJZVEwgIZ0MFJR3oO
# WgEbTUKE0qPPtdpNwTUbPuevq32UFf83qLs6j6PWX8C4xKNrV+3RwZ1xlJxtl4FB
# tKeFib3Nx6NFFJ+7iKBKD6IjMXLErNA0CCcUpdVIQIrku1UoLcWt0dZppriIsZq3
# 6bIwLQPYGcqSUfBqaNtQa3DR4E56f8wlrOCTnYitV+lngc9Yo/j1uD7lKE71rmLN
# DJU=
# SIG # End signature block
