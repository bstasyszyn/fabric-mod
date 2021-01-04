module github.com/hyperledger/fabric/extensions

replace github.com/hyperledger/fabric => ../.

replace github.com/hyperledger/fabric/extensions => ./

require (
	github.com/hyperledger/fabric v2.0.0+incompatible
	github.com/hyperledger/fabric-chaincode-go v0.0.0-20200128192331-2d899240a7ed
	github.com/hyperledger/fabric-protos-go v0.0.0-20200506201313-25f6564b9ac4
	github.com/pkg/errors v0.9.1
	github.com/spf13/viper2015 v1.3.2
	github.com/stretchr/testify v1.5.1
)

//replace github.com/hyperledger/fabric-protos-go => github.com/trustbloc/fabric-protos-go-ext v0.1.5
replace github.com/hyperledger/fabric-protos-go => github.com/bstasyszyn/fabric-protos-go-ext 0ae5075fccb623d7335bf45b190d03f606a26fa3

replace github.com/spf13/viper2015 => github.com/spf13/viper v0.0.0-20150908122457-1967d93db724

go 1.13
