package taint

import (
	"context"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"reflect"
	"testing"
)

//can have nodes, pods  and configMap in a fake clientset unit testing
func fakeClientset(pods []v1.Pod, nodes []v1.Node, configMaps []v1.ConfigMap) (cs kubernetes.Interface) {
	var csObjs []runtime.Object
	for _, node := range nodes {
		csObjs = append(csObjs, node.DeepCopy())
	}
	for _, pod := range pods {
		csObjs = append(csObjs, pod.DeepCopy())
	}
	for _, configMap := range configMaps {
		csObjs = append(csObjs, configMap.DeepCopy())
	}
	cs = fake.NewSimpleClientset(csObjs...)
	return cs
}

//test on whether critical labels and namespace are successfully loaded
func TestTaintSetter_LoadConfig(t *testing.T) {
	type fields struct {
		client kubernetes.Interface
	}
	type args struct {
		config v1.ConfigMap
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		wants  map[string][]string
	}{
		{
			name: "istio-cni config",
			fields: fields{
				client: fakeClientset([]v1.Pod{}, []v1.Node{}, []v1.ConfigMap{istiocniConfig}),
			},
			args: args{
				config: istiocniConfig,
			},
			wants: map[string][]string{
				"istio-cni": {"istio-cni", "kube-system", "app=istio"},
			},
		},
		{
			name: "general config",
			fields: fields{
				client: fakeClientset([]v1.Pod{}, []v1.Node{}, []v1.ConfigMap{istiocniConfig}),
			},
			args: args{
				config: combinedConfig,
			},
			wants: map[string][]string{
				"istio-cni": {"istio-cni", "kube-system", "app=istio"},
				"others":    {"others", "blah", "app=others"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := TaintSetter{
				Client: fake.NewSimpleClientset(),
			}
			ts.LoadConfig(tt.args.config)
			for _, elem := range ts.configs {
				if tt.wants[elem.Name] == nil {
					t.Errorf("wants to load = %v", elem.Name)
				}
				if tt.wants[elem.Name][0] != elem.Name {
					t.Errorf("wants to load name = %v found %v", elem.Name, tt.wants[elem.Name][0])
				}
				if tt.wants[elem.Name][1] != elem.Namespace {
					t.Errorf("wants to load namespace = %v found %v", elem.Namespace, tt.wants[elem.Name][1])
				}
				if tt.wants[elem.Name][2] != elem.LabelSelector {
					t.Errorf("wants to load selector = %v found %v", elem.LabelSelector, tt.wants[elem.Name][2])
				}
			}
		})
	}
}

func TestTaintSetter_AddReadinessTaint(t *testing.T) {
	type fields struct {
		client kubernetes.Interface
	}
	type args struct {
		node v1.Node
	}
	tests := []struct {
		name     string
		fields   fields
		args     args
		wantList []v1.Taint
	}{
		{
			name: "working node already get taint",
			fields: fields{
				client: fakeClientset([]v1.Pod{workingPod}, []v1.Node{testingNode}, []v1.ConfigMap{}),
			},
			args: args{
				testingNode,
			},
			wantList: []v1.Taint{{Key: TaintName, Effect: v1.TaintEffectNoSchedule}},
		},
		{
			name: "plain node add readiness taint",
			fields: fields{
				client: fakeClientset([]v1.Pod{workingPod}, []v1.Node{plainNode}, []v1.ConfigMap{}),
			},
			args: args{
				plainNode,
			},
			wantList: []v1.Taint{{Key: TaintName, Effect: v1.TaintEffectNoSchedule}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := TaintSetter{
				Client: tt.fields.client,
			}
			err := ts.AddReadinessTaint(&tt.args.node)
			if err != nil {
				t.Errorf("error happened in readiness %v", err.Error())
				return
			}
			updatedNode, err := ts.Client.CoreV1().Nodes().Get(context.TODO(), tt.args.node.Name, metav1.GetOptions{})
			if err != nil {
				t.Errorf("error happened in readiness %v", err.Error())
				return
			}
			if !reflect.DeepEqual(updatedNode.Spec.Taints, tt.wantList) {
				t.Errorf("AddReadinessTaint() gotList = %v, want %v", updatedNode.Spec.Taints, tt.wantList)
			}
		})
	}
}
func TestTaintSetter_HasReadinessTaint(t *testing.T) {
	type fields struct {
		client kubernetes.Interface
	}
	type args struct {
		node v1.Node
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "working node already get taint",
			fields: fields{
				client: fakeClientset([]v1.Pod{workingPod}, []v1.Node{testingNode}, []v1.ConfigMap{}),
			},
			args: args{
				testingNode,
			},
			want: true,
		},
		{
			name: "plain node add readiness taint",
			fields: fields{
				client: fakeClientset([]v1.Pod{workingPod}, []v1.Node{plainNode}, []v1.ConfigMap{}),
			},
			args: args{
				plainNode,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := TaintSetter{
				Client: tt.fields.client,
			}
			hastaint := ts.HasReadinessTaint(&tt.args.node)
			if hastaint != tt.want {
				t.Errorf("AddReadinessTaint() gotList = %v, want %v", hastaint, tt.want)
			}
		})
	}
}
func TestTaintSetter_RemoveReadinessTaint(t *testing.T) {
	type fields struct {
		client kubernetes.Interface
	}
	type args struct {
		node v1.Node
	}
	tests := []struct {
		name     string
		fields   fields
		args     args
		wantList []v1.Taint
	}{
		{
			name: "working node already get taint",
			fields: fields{
				client: fakeClientset([]v1.Pod{workingPod}, []v1.Node{testingNode}, []v1.ConfigMap{}),
			},
			args: args{
				testingNode,
			},
			wantList: []v1.Taint{},
		},
		{
			name: "plain node add readiness taint",
			fields: fields{
				client: fakeClientset([]v1.Pod{workingPod}, []v1.Node{plainNode}, []v1.ConfigMap{}),
			},
			args: args{
				plainNode,
			},
			wantList: []v1.Taint{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := TaintSetter{
				Client: tt.fields.client,
			}
			err := ts.RemoveReadinessTaint(&tt.args.node)
			if err != nil {
				t.Errorf("error happened in readiness %v", err.Error())
			}
			gotNode, _ := ts.Client.CoreV1().Nodes().Get(context.TODO(), tt.args.node.Name, metav1.GetOptions{})
			if !reflect.DeepEqual(gotNode.Spec.Taints, tt.wantList) {
				t.Errorf("AddReadinessTaint() gotList = %v, want %v", gotNode.Spec.Taints, tt.wantList)
			}
		})
	}
}

func TestGetNodeLatestReadiness(t *testing.T) {
	type args struct {
		node v1.Node
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "working node is ready",
			args: args{
				testingNode,
			},
			want: true,
		},
		{
			name: "not ready node example",
			args: args{
				unreadyNode,
			},
			want: false,
		},
		{
			name: "empty case",
			args: args{
				plainNode,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetNodeLatestReadiness(tt.args.node)
			if got != tt.want {
				t.Fatalf("want %v, get %v", got, tt.want)
			}
		})
	}
}
