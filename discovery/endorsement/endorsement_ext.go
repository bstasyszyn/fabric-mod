/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package endorsement

import (
	"github.com/pkg/errors"

	"github.com/hyperledger/fabric/common/policies"
	"github.com/hyperledger/fabric/common/policies/inquire"
	gossipapi "github.com/hyperledger/fabric/extensions/gossip/api"
	"github.com/hyperledger/fabric/gossip/common"
	"github.com/hyperledger/fabric/gossip/discovery"
)

// PeersByPolicy returns a PeerPolicyDescriptor for a given set of peers in the channel according to the given policy and peer filter
func (ea *endorsementAnalyzer) PeersByPolicy(
	chainID common.ChannelID,
	policy policies.InquireablePolicy,
	filter func(member discovery.NetworkMember) bool) (*gossipapi.PeerPolicyDescriptor, error) {

	identities := ea.IdentityInfo()

	// Filter out peers according to the given filter
	chanMembership := ea.PeersOfChannel(chainID).Filter(filter)

	logger.Infof("[%s] Peers of channel after filter: %+v", chainID, chanMembership)

	channelMembersByID := chanMembership.ByID()

	// Choose only the alive messages of those that have joined the channel
	aliveMembership := ea.Peers().Intersect(chanMembership)
	membersByID := aliveMembership.ByID()
	// Compute a mapping between the PKI-IDs of members to their identities

	identitiesOfMembers := computeIdentitiesOfMembers(identities, membersByID)

	principalsSets, err := ea.computePeerPolicyPrincipalSets(policy, func(set policies.PrincipalSet) bool { return true })
	if err != nil {
		logger.Warningf("Principal set computation failed: %v", err)
		return nil, errors.WithStack(err)
	}

	return ea.computePeerPolicyResponse(&context{
		channel:             string(chainID),
		aliveMembership:     aliveMembership,
		principalsSets:      principalsSets,
		channelMembersById:  channelMembersByID,
		identitiesOfMembers: identitiesOfMembers,
		chaincodeMapping:    channelMembersByID, // Ensure that no peer is filtered out using the chaincode filter
	})
}

type principalFilter func(policies.PrincipalSet) bool

func (ea *endorsementAnalyzer) computePeerPolicyPrincipalSets(policy policies.InquireablePolicy, filter principalFilter) (policies.PrincipalSets, error) {
	var cmpsets inquire.ComparablePrincipalSets
	for _, ps := range policy.SatisfiedBy() {
		if !filter(ps) {
			logger.Info(ps, "filtered out due to chaincodes not being installed on the corresponding organizations")
			continue
		}
		cps := inquire.NewComparablePrincipalSet(ps)
		if cps == nil {
			return nil, errors.New("failed creating a comparable principal set")
		}
		cmpsets = append(cmpsets, cps)
	}
	if len(cmpsets) == 0 {
		return nil, errors.New("insufficient organizations available to satisfy endorsement policy")
	}

	return cmpsets.ToPrincipalSets(), nil
}

func (ea *endorsementAnalyzer) computePeerPolicyResponse(ctx *context) (*gossipapi.PeerPolicyDescriptor, error) {
	// mapPrincipalsToGroups returns a mapping from principals to their corresponding groups.
	// groups are just human readable representations that mask the principals behind them
	principalGroups := mapPrincipalsToGroups(ctx.principalsSets)
	// principalsToPeersGraph computes a bipartite graph (V1 U V2 , E)
	// such that V1 is the peers, V2 are the principals,
	// and each e=(peer,principal) is in E if the peer satisfies the principal
	satGraph := principalsToPeersGraph(principalAndPeerData{
		members: ctx.aliveMembership,
		pGrps:   principalGroups,
	}, ea.satisfiesPrincipal(ctx.channel, ctx.identitiesOfMembers))

	layouts := computeLayouts(ctx.principalsSets, principalGroups, satGraph)
	if len(layouts) == 0 {
		return nil, errors.New("cannot satisfy any principal combination")
	}

	criteria := &peerMembershipCriteria{
		possibleLayouts:  layouts,
		satGraph:         satGraph,
		chanMemberById:   ctx.channelMembersById,
		idOfMembers:      ctx.identitiesOfMembers,
		chaincodeMapping: ctx.chaincodeMapping,
	}

	return &gossipapi.PeerPolicyDescriptor{
		Layouts:       layouts,
		PeersByGroups: endorsersByGroup(criteria),
	}, nil
}
