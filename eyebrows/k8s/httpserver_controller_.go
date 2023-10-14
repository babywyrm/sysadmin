/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"github.com/william20111/go-thousandeyes"
	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	devnetv1alpha1 "github.com/CiscoDevNet/thousandeyes-kubernetes-operator/api/v1alpha1"
)

const httpserverFinalizer = "thousandeyes.devnet.cisco.com.httpserver.finalizer"

// HTTPServerTestReconciler reconciles a HTTPServerTest object
type HTTPServerTestReconciler struct {
	client.Client
	Log                logr.Logger
	Scheme             *runtime.Scheme
	ThousandEyesClient *thousandeyes.Client
}

//+kubebuilder:rbac:groups=devnet.cisco.com,resources=httpservertests,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=devnet.cisco.com,resources=httpservertests/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=devnet.cisco.com,resources=httpservertests/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the HTTPServerTest object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.7.2/pkg/reconcile
func (r *HTTPServerTestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = r.Log.WithValues("httpservertest", req.NamespacedName)

	// fetch the instance
	pl := &devnetv1alpha1.HTTPServerTest{}
	err := r.Get(ctx, req.NamespacedName, pl)
	if err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	tests, _ := r.ThousandEyesClient.GetTests()
	if tests != nil {
		for _, test := range *tests {
			if test.TestName == pl.Name {
				pl.Spec.HTTPServer.TestID = test.TestID
				break
			}
		}
	}
	// check if the thousandeyes-test instance is marked to be deleted, which is
	// indicated by the deletion timestamp being set
	isTeTestMarkedToBeDeleted := pl.GetDeletionTimestamp() != nil
	if isTeTestMarkedToBeDeleted {
		if controllerutil.ContainsFinalizer(pl, httpserverFinalizer) {
			// delete thousandeyes test from server
			if pl.Spec.HTTPServer.TestID != 0 {
				err = r.ThousandEyesClient.DeleteHTTPServer(pl.Spec.HTTPServer.TestID)
				if err != nil {
					return ctrl.Result{}, err
				}
			}
			controllerutil.RemoveFinalizer(pl, httpserverFinalizer)
			err := r.Update(ctx, pl)
			if err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	if !controllerutil.ContainsFinalizer(pl, httpserverFinalizer) {
		controllerutil.AddFinalizer(pl, httpserverFinalizer)
		err := r.Update(ctx, pl)
		if err != nil {
			return ctrl.Result{}, err
		}
	}

	data := HTTPServer(pl.Spec.HTTPServer)

	agents, err := r.ThousandEyesClient.GetAgents()
	if err != nil {
		return ctrl.Result{}, err
	}
	data.Agents = Agents(pl.Spec.Agents, *agents)

	if len(pl.Spec.AlertRules) != 0 {
		alertRules, err := r.ThousandEyesClient.GetAlertRules()
		if err != nil {
			return ctrl.Result{}, err
		}
		data.AlertRules = AlertRules(pl.Spec.AlertRules, *alertRules)
	}

	if pl.Spec.HTTPServer.TestID != 0 {
		//check if the test needs to be updated
		httpServer, err := r.ThousandEyesClient.GetHTTPServer(pl.Spec.HTTPServer.TestID)
		if err != nil {
			return ctrl.Result{}, err
		}
		if !CompareHTTPServer(pl.Spec.HTTPServer, *httpServer) {
			_, err := r.ThousandEyesClient.UpdateHTTPServer(pl.Spec.HTTPServer.TestID, data)
			if err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, nil
	}
	data.TestName = pl.Name
	_, err = r.ThousandEyesClient.CreateHTTPServer(data)
	if err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *HTTPServerTestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&devnetv1alpha1.HTTPServerTest{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: maxConcurrentReconciles,
		}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}
