rule Contains_evil_string
{
  meta:
    author = "team"
    purpose = "demo"
  strings:
    $s1 = "evil" nocase
  condition:
    $s1
}
