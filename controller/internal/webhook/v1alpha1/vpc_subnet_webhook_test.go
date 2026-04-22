package v1alpha1

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("Vpc/Subnet webhooks", func() {
	It("rejects deleting the default VPC", func() {
		var vpc juneauv1alpha1.Vpc
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: "default"}, &vpc)).To(Succeed())

		err := webhookK8sClient.Delete(context.Background(), &vpc)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("default Vpc cannot be deleted"))
	})

	It("rejects deleting the default Subnet", func() {
		var subnet juneauv1alpha1.Subnet
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: "default"}, &subnet)).To(Succeed())

		err := webhookK8sClient.Delete(context.Background(), &subnet)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("default Subnet cannot be deleted"))
	})

	It("rejects creating a non-default Subnet in the default VPC", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("subnet")},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:  "default",
				CIDR: webhookUniqueSubnetCIDR(),
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("only the default Subnet can reference the default Vpc"))
	})

	It("rejects creating a Subnet referencing a nonexistent VPC", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("subnet")},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:  webhookUniqueTestName("missing-vpc"),
				CIDR: webhookUniqueSubnetCIDR(),
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced Vpc does not exist"))
	})

	It("rejects creating a Subnet with malformed CIDR", func() {
		vpcName := createWebhookVpc()

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("subnet")},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:  vpcName,
				CIDR: "10.0.0.0",
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("must be a valid IPv4 CIDR"))
	})

	It("rejects creating a too-large Subnet", func() {
		vpcName := createWebhookVpc()

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("subnet")},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:  vpcName,
				CIDR: "10.0.0.0/15",
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("CIDR prefix length must be between /16 and /28"))
	})

	It("rejects creating a too-small Subnet", func() {
		vpcName := createWebhookVpc()

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("subnet")},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:  vpcName,
				CIDR: "10.0.0.0/29",
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("CIDR prefix length must be between /16 and /28"))
	})

	It("rejects overlapping subnets in the same VPC", func() {
		vpcName := createWebhookVpc()
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("subnet")},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:  vpcName,
				CIDR: "10.90.0.0/24",
			},
		})).To(Succeed())

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("subnet")},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:  vpcName,
				CIDR: "10.90.0.128/25",
			},
		})

		// This intentionally captures currently missing overlap validation.
		Expect(err).To(HaveOccurred(), "missing overlap validation currently allows overlapping subnets in the same VPC")
	})
})

func createWebhookVpc() string {
	name := webhookUniqueTestName("vpc")
	Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Vpc{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	})).To(Succeed())
	return name
}

func webhookUniqueTestName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

func webhookUniqueSubnetCIDR() string {
	octet := time.Now().UnixNano()%200 + 20
	return fmt.Sprintf("10.%d.0.0/24", octet)
}
