# Helm Charts for ArcGIS Enterprise on Kubernetes

## Introduction

Welcome to Helm Charts for ArcGIS Enterprise on Kubernetes! This is an alternative method to deploying ArcGIS Enterprise on Kubernetes that can easily be incorporated into your existing automated solutions.

## Why use Helm?

Helm is a user-friendly, package manager for Kubernetes. For ArcGIS Enterprise on Kubernetes, Helm is an additional tool to help manage complexity, provide repeatablility and provide a seamless experience across supported Kubernetes providers.

## System Requirements

The full system requirements are listed in the [Enterprise documentation](https://enterprise-k8s.arcgis.com/en/latest/deploy/system-requirements.htm). For Helm, additional requirements are listed below:

* Helm CLI client v3.0.0+

## Steps to Deploy ArcGIS Enterprise on Kubernetes using Helm

#### Modifying values.yaml (Optional)

Once you have obtained the chart archive (.tgz) from My Esri, open a terminal as an administrator on your Kubernetes client machine. Extract the file and change directories inside the helm/arcgis-enterprise folder. Once there, there will be a values.yaml file.

This file will contain the following sections that you will need to edit:

* Container Image Registry Details
* Installation Inputs

Each of these sections contain values that you will need to customize to your unique deployment. Once you have made the appropriate changes, save the file and exit.

If you choose to not perform this optional step, the following step outlines how you can still install the Helm chart without modifying values.yaml.

#### Installing the Chart

Once values.yaml has been modified, you're ready to use helm install to deploy the chart. Assuming you have performed the optional first step and modified the values.yaml file, the simplest way to do this is to run the following command:

```helm install -n <your namespace> arcgis scripts/helm/arcgis-enterprise```

The above command proceeds to deploy ArcGIS Enterprise on Kubernetes. As this is running, you can run ```helm status arcgis -n <your namespace>``` to track the status of the chart installation. Additionally, you can run command ```helm list -n <your namespace>``` to check the installed releases within your namespace.

If you elected to not perform the previous optional step, you can still install the Helm chart. You will need to expand the ```helm install``` command to pass in your unique values. An example is shown below:

```
helm install \
  --set image.username=<your username> \
  --set image.password=<your password> \
  --set install.ingressType=<your Ingress type> \
  --set install.loadBalancerType=<your load balancer type> \
  --set install.context=<your context> \
  --set install.enterpriseFQDN=<your FQDN> \
  --set install.ingress.tls.secretName=<your TLS secret>
```

The above is an alternative means to installing the Helm chart. Additionally, you can choose to fill out some parameters in the ```values.yaml``` file and pass other parameters via the ```helm install``` method shown above; this mixed option is also supported. Once the Helm chart has successfully been installed, you will receive a URL to create an ArcGIS Enterprise Organization using the Enterprise Manager. Copy that URL in a browser and follow the steps to create your Enterprise organization.

### Chart Values

| Parameter | Description | Default |
|-----|------|---------|
| `image.username` | Username for your container registry. | `""` |
| `image.password` | Password for your container registry. | `""` |
| `image.repository` | Container repository for images to be pulled. | `""` |
| `image.tag` | Tag for the images the container registry pulls. | `""` |
| `install.enterpriseFQDN` | Fully Qualified Domain Name to be used with ArcGIS Enterprise on Kubernetes. | `""` |
| `install.context` | Context path to be used in the URL for your Enterprise FQDN. | `"arcgis"` |
| `install.ingress.ingressType` | Exposes the Ingress controller via NodePort or LoadBalancer. | `"NodePort"` |
| `install.ingress.loadBalancerType` | If Ingress Type is LoadBalancer, then define the load balancer type. Otherwise, leave blank. | `""`
| `install.ingress.loadBalancerIP` | Use a pre-configured static public IP address for your load balancer. | `""`
| `install.ingress.nodePortHttps` | Specify NodePort in the range 30,000-32,767 or leave blank. | `""`
| `install.ingress.useOpenshiftRoute` | For OpenShift deployments, specify if an OpenShift Route is being used. | `false`
| `install.ingress.tls.secretName` | Define your pre-created TLS secret to use with the Ingress. | `""`
| `install.ingress.tls.selfSignCN` | Define a self-signed certificate common name. | `""`
| `common.verbose` | Allow commands to be run with a verbose setting. | `false`

NOTE: The `install.ingress.tls` options are mutually exlusive so you can only define one option at a time.

## Undeploy ArcGIS Enterprise on Kubernetes using Helm

To undeploy ArcGIS Enterprise on Kubernetes using Helm, simply run the following:

```helm uninstall arcgis -n <your namespace>```
