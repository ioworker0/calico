// Copyright (c) 2024 Tigera, Inc. All rights reserved.

// Code generated by lister-gen. DO NOT EDIT.

package v3

import (
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// BGPConfigurationLister helps list BGPConfigurations.
// All objects returned here must be treated as read-only.
type BGPConfigurationLister interface {
	// List lists all BGPConfigurations in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v3.BGPConfiguration, err error)
	// Get retrieves the BGPConfiguration from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v3.BGPConfiguration, error)
	BGPConfigurationListerExpansion
}

// bGPConfigurationLister implements the BGPConfigurationLister interface.
type bGPConfigurationLister struct {
	indexer cache.Indexer
}

// NewBGPConfigurationLister returns a new BGPConfigurationLister.
func NewBGPConfigurationLister(indexer cache.Indexer) BGPConfigurationLister {
	return &bGPConfigurationLister{indexer: indexer}
}

// List lists all BGPConfigurations in the indexer.
func (s *bGPConfigurationLister) List(selector labels.Selector) (ret []*v3.BGPConfiguration, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v3.BGPConfiguration))
	})
	return ret, err
}

// Get retrieves the BGPConfiguration from the index for a given name.
func (s *bGPConfigurationLister) Get(name string) (*v3.BGPConfiguration, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v3.Resource("bgpconfiguration"), name)
	}
	return obj.(*v3.BGPConfiguration), nil
}
