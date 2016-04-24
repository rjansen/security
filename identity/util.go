package identity

func ContainsRole(roles []string, r string) bool {
    for _, v := range roles {
        if v == r {
            return true
        }
    }
    return false
}
