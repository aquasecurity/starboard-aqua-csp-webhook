// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"time"

	v1alpha1 "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	scheme "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// ConfigAuditReportsGetter has a method to return a ConfigAuditReportInterface.
// A group's client should implement this interface.
type ConfigAuditReportsGetter interface {
	ConfigAuditReports(namespace string) ConfigAuditReportInterface
}

// ConfigAuditReportInterface has methods to work with ConfigAuditReport resources.
type ConfigAuditReportInterface interface {
	Create(*v1alpha1.ConfigAuditReport) (*v1alpha1.ConfigAuditReport, error)
	Update(*v1alpha1.ConfigAuditReport) (*v1alpha1.ConfigAuditReport, error)
	Delete(name string, options *v1.DeleteOptions) error
	DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error
	Get(name string, options v1.GetOptions) (*v1alpha1.ConfigAuditReport, error)
	List(opts v1.ListOptions) (*v1alpha1.ConfigAuditReportList, error)
	Watch(opts v1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.ConfigAuditReport, err error)
	ConfigAuditReportExpansion
}

// configAuditReports implements ConfigAuditReportInterface
type configAuditReports struct {
	client rest.Interface
	ns     string
}

// newConfigAuditReports returns a ConfigAuditReports
func newConfigAuditReports(c *AquasecurityV1alpha1Client, namespace string) *configAuditReports {
	return &configAuditReports{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the configAuditReport, and returns the corresponding configAuditReport object, and an error if there is any.
func (c *configAuditReports) Get(name string, options v1.GetOptions) (result *v1alpha1.ConfigAuditReport, err error) {
	result = &v1alpha1.ConfigAuditReport{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("configauditreports").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of ConfigAuditReports that match those selectors.
func (c *configAuditReports) List(opts v1.ListOptions) (result *v1alpha1.ConfigAuditReportList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.ConfigAuditReportList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("configauditreports").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do().
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested configAuditReports.
func (c *configAuditReports) Watch(opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("configauditreports").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch()
}

// Create takes the representation of a configAuditReport and creates it.  Returns the server's representation of the configAuditReport, and an error, if there is any.
func (c *configAuditReports) Create(configAuditReport *v1alpha1.ConfigAuditReport) (result *v1alpha1.ConfigAuditReport, err error) {
	result = &v1alpha1.ConfigAuditReport{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("configauditreports").
		Body(configAuditReport).
		Do().
		Into(result)
	return
}

// Update takes the representation of a configAuditReport and updates it. Returns the server's representation of the configAuditReport, and an error, if there is any.
func (c *configAuditReports) Update(configAuditReport *v1alpha1.ConfigAuditReport) (result *v1alpha1.ConfigAuditReport, err error) {
	result = &v1alpha1.ConfigAuditReport{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("configauditreports").
		Name(configAuditReport.Name).
		Body(configAuditReport).
		Do().
		Into(result)
	return
}

// Delete takes name of the configAuditReport and deletes it. Returns an error if one occurs.
func (c *configAuditReports) Delete(name string, options *v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("configauditreports").
		Name(name).
		Body(options).
		Do().
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *configAuditReports) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	var timeout time.Duration
	if listOptions.TimeoutSeconds != nil {
		timeout = time.Duration(*listOptions.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("configauditreports").
		VersionedParams(&listOptions, scheme.ParameterCodec).
		Timeout(timeout).
		Body(options).
		Do().
		Error()
}

// Patch applies the patch and returns the patched configAuditReport.
func (c *configAuditReports) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.ConfigAuditReport, err error) {
	result = &v1alpha1.ConfigAuditReport{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("configauditreports").
		SubResource(subresources...).
		Name(name).
		Body(data).
		Do().
		Into(result)
	return
}
