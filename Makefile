.ONESHELL:

NAME ?= $(shell basename $(CURDIR))
PATTERN_DIR ?= $(CURDIR)

ifneq ($(origin TARGET_SITE), undefined)
  TARGET_SITE_OPT=--set main.clusterGroupName=$(TARGET_SITE)
endif

# Set this to true if you want to skip any origin validation
DISABLE_VALIDATE_ORIGIN ?= false
ifeq ($(DISABLE_VALIDATE_ORIGIN),true)
  VALIDATE_ORIGIN :=
else
  VALIDATE_ORIGIN := validate-origin
endif

SECRETS_BACKING_STORE ?= $(shell yq '.global.secretStore.backend' values-global.yaml 2>/dev/null)
ifeq ($(SECRETS_BACKING_STORE),null)
  SECRETS_BACKING_STORE=vault
endif

# This variable can be set in order to pass additional helm arguments from the
# the command line. I.e. we can set things without having to tweak values files
EXTRA_HELM_OPTS ?=

# This variable can be set in order to pass additional ansible-playbook arguments from the
# the command line. I.e. we can set -vvv for more verbose logging
EXTRA_PLAYBOOK_OPTS ?=

# INDEX_IMAGES=registry-proxy.engineering.redhat.com/rh-osbs/iib:394248
# or
# INDEX_IMAGES=registry-proxy.engineering.redhat.com/rh-osbs/iib:394248,registry-proxy.engineering.redhat.com/rh-osbs/iib:394249
INDEX_IMAGES ?=

# git branch --show-current is also available as of git 2.22, but we will use this for compatibility
TARGET_BRANCH ?= $(shell git rev-parse --abbrev-ref HEAD)

#default to the branch remote
TARGET_ORIGIN ?= $(shell git config branch.$(TARGET_BRANCH).remote)

# This is to ensure that whether we start with a git@ or https:// URL, we end up with an https:// URL
# This is because we expect to use tokens for repo authentication as opposed to SSH keys
TARGET_REPO=$(shell git ls-remote --get-url --symref $(TARGET_ORIGIN) | sed -e 's/.*URL:[[:space:]]*//' -e 's%^git@%%' -e 's%^https://%%' -e 's%:%/%' -e 's%^%https://%')

UUID_FILE ?= ~/.config/validated-patterns/pattern-uuid
UUID_HELM_OPTS ?=

# --set values always take precedence over the contents of -f
ifneq ("$(wildcard $(UUID_FILE))","")
	UUID := $(shell cat $(UUID_FILE))
	UUID_HELM_OPTS := --set main.analyticsUUID=$(UUID)
endif

# Set the secret name *and* its namespace when deploying from private repositories
# The format of said secret is documented here: https://argo-cd.readthedocs.io/en/stable/operator-manual/declarative-setup/#repositories
TOKEN_SECRET ?=
TOKEN_NAMESPACE ?=

HELM_OPTS := -f values-global.yaml
HELM_OPTS += --set main.git.revision=$(TARGET_BRANCH)
HELM_OPTS += $(TARGET_SITE_OPT)
HELM_OPTS += $(UUID_HELM_OPTS)
HELM_OPTS += $(EXTRA_HELM_OPTS)

ifeq ($(TOKEN_SECRET),)
  HELM_OPTS += --set main.git.repoURL="$(TARGET_REPO)"
else
  # When we are working with a private repository we do not escape the git URL as it might be using an ssh secret which does not use https://
  TARGET_CLEAN_REPO=$(shell git ls-remote --get-url --symref $(TARGET_ORIGIN))
  HELM_OPTS += --set main.tokenSecret=$(TOKEN_SECRET)
  HELM_OPTS += --set main.tokenSecretNamespace=$(TOKEN_NAMESPACE)
  HELM_OPTS += --set main.git.repoURL="$(TARGET_CLEAN_REPO)"
endif

# Helm does the right thing and fetches all the tags and detects the newest one
PATTERN_INSTALL_CHART ?= oci://quay.io/hybridcloudpatterns/pattern-install

##@ Utility and Authentication Tasks

.PHONY: argocd-login
argocd-login: ## Login to validated patterns argocd instances
	@ARGOCD_NAMESPACES=$(oc get argoCD -A -o jsonpath='{.items[*].metadata.namespace}')
	if [ -z "$ARGOCD_NAMESPACES" ]; then
		echo "Error: No Argo CD instances found in the cluster."
		exit 1
	fi
	NAMESPACES=($ARGOCD_NAMESPACES)
	if [ ${#NAMESPACES[@]} -lt 2 ]; then
		echo "Error: Less than two Argo CD instances found. Found instances in namespaces: $ARGOCD_NAMESPACES"
		exit 1
	fi
	for NAMESPACE in ${NAMESPACES[@]}; do
		ARGOCD_INSTANCE=$(oc get argocd -n "$NAMESPACE" -o jsonpath='{.items[0].metadata.name}')
		SERVER_URL=$(oc get route "$ARGOCD_INSTANCE"-server -n "$NAMESPACE" -o jsonpath='{.status.ingress[0].host}')
		PASSWORD=$(oc get secret "$ARGOCD_INSTANCE"-cluster -n "$NAMESPACE" -o jsonpath='{.data.admin\.password}' | base64 -d)
		echo $PASSWORD
		argocd login --skip-test-tls --insecure --grpc-web "$SERVER_URL" --username "admin" --password "$PASSWORD"
		if [ "$?" -ne 0 ]; then
			echo "Login to Argo CD $SERVER_URL failed. Exiting."
			exit 1
		fi
	done

.PHONY: token-kubeconfig
token-kubeconfig: ## Create a local ~/.kube/config with password (not usually needed)
	ansible-playbook -e pattern_dir="$(PATTERN_DIR)" -e kubeconfig_file="~/.kube/config" $(EXTRA_PLAYBOOK_OPTS) "rhvp.cluster_utils.write_token_kubeconfig"

.PHONY: help
help: ## This help message
	@echo "Pattern: $(NAME)"
	echo "Pattern Dir: $(PATTERN_DIR)"
	awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^(\s|[a-zA-Z_0-9-])+:.*?##/ { printf "  \033[36m%-35s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Preview and Template Tasks

#  Makefiles in the individual patterns should call these targets explicitly
#  e.g. from industrial-edge: make -f common/Makefile show
.PHONY: show
show: ## Show the starting template without installing it
	@helm template $(PATTERN_INSTALL_CHART) --name-template $(NAME) $(HELM_OPTS) 2>/dev/null

preview-all: ## (EXPERIMENTAL) Previews all applications on hub and managed clusters
	@echo "NOTE: This is just a tentative approximation of rendering all hub and managed clusters templates"
	HUB=$$(yq ".main.clusterGroupName" values-global.yaml)
	MANAGED_CLUSTERS=$$(yq ".clusterGroup.managedClusterGroups.[].name" "values-$$HUB.yaml")
	ALL_CLUSTERS="$$HUB $$MANAGED_CLUSTERS"
	CLUSTER_INFO_OUT=$$(oc cluster-info 2>&1)
	CLUSTER_INFO_RET=$$?
	if [ $$CLUSTER_INFO_RET -ne 0 ]; then
		echo "Could not access the cluster:"
		echo "$$CLUSTER_INFO_OUT"
		exit 1
	fi
	for cluster in $$ALL_CLUSTERS; do
		APPS="clustergroup $$(yq -r '.clusterGroup.applications.[].name | select(. != null)' "values-$$cluster.yaml" 2>/dev/null)"
		for app in $$APPS; do
			printf "\n# Parsing application $$app from cluster $$cluster\n"
			$(MAKE) -s --no-print-directory preview-$$app CLUSTERGROUP="$$cluster" TARGET_REPO="$(TARGET_REPO)" TARGET_BRANCH="$(TARGET_BRANCH)" 2>/dev/null
		done
	done

preview-%:
	SITE='$(CLUSTERGROUP)'
	APPNAME='$*'
	GIT_REPO='$(TARGET_REPO)'
	GIT_BRANCH='$(TARGET_BRANCH)'

	if [ "$$APPNAME" != "clustergroup" ]; then
		APP=$$(yq -r ".clusterGroup.applications | with_entries(select(.value.name == \"$$APPNAME\")) | keys | .[0]" "values-$$SITE.yaml")
		isLocalHelmChart=$$(yq -r ".clusterGroup.applications.$$APP.path" "values-$$SITE.yaml")
		if [ "$$isLocalHelmChart" != "null" ]; then
			chart=$$(yq -r ".clusterGroup.applications.$$APP.path" "values-$$SITE.yaml")
		else
			helmrepo=$$(yq -r ".clusterGroup.applications.$$APP.repoURL" "values-$$SITE.yaml")
			helmrepo="$${helmrepo:+oci://quay.io/hybridcloudpatterns}"
			chartversion=$$(yq -r ".clusterGroup.applications.$$APP.chartVersion" "values-$$SITE.yaml")
			chartname=$$(yq -r ".clusterGroup.applications.$$APP.chart" "values-$$SITE.yaml")
			chart="$$helmrepo/$$chartname --version $$chartversion"
		fi
		namespace=$$(yq -r ".clusterGroup.applications.$$APP.namespace" "values-$$SITE.yaml")
	else
		APP="$$APPNAME"
		clusterGroupChartVersion=$$(yq -r ".main.multiSourceConfig.clusterGroupChartVersion" values-global.yaml)
		helmrepo="oci://quay.io/hybridcloudpatterns"
		chart="$$helmrepo/clustergroup --version $$clusterGroupChartVersion"
		namespace="openshift-operators"
	fi
	pattern=$$(yq -r ".global.pattern" values-global.yaml)
	platform="$${OCP_PLATFORM:-$$(oc get Infrastructure.config.openshift.io/cluster -o jsonpath='{.spec.platformSpec.type}')}"
	ocpversion="$${OCP_VERSION:-$$(oc get clusterversion/version -o jsonpath='{.status.desired.version}' | awk -F. '{print $$1"."$$2}')}"
	domain="$${OCP_DOMAIN:-$$(oc get Ingress.config.openshift.io/cluster -o jsonpath='{.spec.domain}' | sed 's/^apps.//')}"
	CLUSTER_OPTS="--set global.pattern=$$pattern"
	CLUSTER_OPTS="$$CLUSTER_OPTS --set global.repoURL=$$GIT_REPO"
	CLUSTER_OPTS="$$CLUSTER_OPTS --set main.git.repoURL=$$GIT_REPO"
	CLUSTER_OPTS="$$CLUSTER_OPTS --set main.git.revision=$$GIT_BRANCH"
	CLUSTER_OPTS="$$CLUSTER_OPTS --set global.namespace=$$namespace"
	CLUSTER_OPTS="$$CLUSTER_OPTS --set global.hubClusterDomain=apps.$$domain"
	CLUSTER_OPTS="$$CLUSTER_OPTS --set global.localClusterDomain=apps.$$domain"
	CLUSTER_OPTS="$$CLUSTER_OPTS --set global.clusterDomain=$$domain"
	CLUSTER_OPTS="$$CLUSTER_OPTS --set global.clusterVersion=$$ocpversion"
	CLUSTER_OPTS="$$CLUSTER_OPTS --set global.clusterPlatform=$$platform"
	VALUE_FILES="-f values-global.yaml -f values-$$SITE.yaml"
	sharedValueFiles=$$(yq -r '.clusterGroup.sharedValueFiles | select(. != null) | .[]' "values-$$SITE.yaml" 2>/dev/null)
	appValueFiles=$$(yq -r ".clusterGroup.applications.$$APP.extraValueFiles | select(. != null) | .[]" "values-$$SITE.yaml" 2>/dev/null)

	# This loop now correctly mimics the original script's 'replaceGlobals' function.
	for line in $$sharedValueFiles; do
		# This pipeline first removes quotes and normalizes the template syntax,
		# then it substitutes the platform, version, and domain variables.
		file=$$(echo "$$line" | sed -e "s/'//g" -e 's/\$.Values/.Values/g' -e "s/{{.Values.global.clusterPlatform}}/$$platform/g" -e "s/{{.Values.global.clusterVersion}}/$$ocpversion/g" -e "s/{{.Values.global.clusterDomain}}/$$domain/g")
		if [ -f "$$file" ]; then
			VALUE_FILES="$$VALUE_FILES -f $$file"
		fi
	done
	for line in $$appValueFiles; do
		file=$$(echo "$$line" | sed -e "s/'//g" -e 's/\$.Values/.Values/g' -e "s/{{.Values.global.clusterPlatform}}/$$platform/g" -e "s/{{.Values.global.clusterVersion}}/$$ocpversion/g" -e "s/{{.Values.global.clusterDomain}}/$$domain/g")
		if [ -f "$$file" ]; then
			VALUE_FILES="$$VALUE_FILES -f $$file"
		fi
	done

	isKustomize=$$(yq -r ".clusterGroup.applications.$$APP.kustomize" "values-$$SITE.yaml")
	overrides=$$(yq -r ".clusterGroup.applications.$$APP.overrides[] | select(. != null)" "values-$$SITE.yaml" 2>/dev/null | tr -d '\n' | sed -e 's/name:/ --set/g; s/value: /=/g')
	if [ "$$isKustomize" == "true" ]; then
		kustomizePath=$$(yq -r ".clusterGroup.applications.$$APP.path" "values-$$SITE.yaml")
		repoURL=$$(yq -r ".clusterGroup.applications.$$APP.repoURL" "values-$$SITE.yaml")
		if [[ "$$repoURL" == http* ]] || [[ "$$repoURL" == git@* ]]; then
			kustomizePath="$$repoURL/$$kustomizePath"
		fi
		oc kustomize "$$kustomizePath"
	else
		helm template $$chart --name-template $$APP -n $$namespace $$VALUE_FILES $$overrides $$CLUSTER_OPTS
	fi

##@ Installation and Deployment Tasks

.PHONY: operator-deploy
operator-deploy operator-upgrade: validate-prereq $(VALIDATE_ORIGIN) validate-cluster ## Runs helm install
	@RUNS=10
	WAIT=15
	echo -n "Installing pattern: "
	for i in $(seq 1 $RUNS); do
		OUT=$(helm template --include-crds --name-template $(NAME) $(PATTERN_INSTALL_CHART) $(HELM_OPTS) 2>&1 | oc apply -f- 2>&1)
		ret=$?
		if [ $ret -eq 0 ]; then
			break
		else
			echo -n "."
			sleep "$WAIT"
		fi
	done
	if [ $i -eq $RUNS ]; then
		echo "Installation failed [$i/$RUNS]. Error:"
		echo "$OUT"
		exit 1
	fi
	echo "Done"

.PHONY: uninstall
uninstall: ## Runs helm uninstall
	CSV=$(oc get subscriptions -n openshift-operators openshift-gitops-operator -ojsonpath={.status.currentCSV})
	helm uninstall $(NAME)
	@oc delete csv -n openshift-operators $CSV

.PHONY: install
install: operator-deploy post-install ## Installs the pattern and loads the secrets
	@echo "Installed"

.PHONY: post-install
post-install: ## Post-install tasks
	make load-secrets
	@echo "Done"

##@ Secret Management Tasks

.PHONY: display-secrets-info
display-secrets-info: ## Display information about secrets configuration
# 	SECRETS_BACKING_STORE=$$(yq -e '.global.secretStore.backend' values-global.yaml 2>/dev/null || echo "vault")
	ansible-playbook -e pattern_name="$(NAME)" -e pattern_dir="$(PATTERN_DIR)" -e secrets_backing_store="$(SECRETS_BACKING_STORE)" -e hide_sensitive_output=false $(EXTRA_PLAYBOOK_OPTS) "rhvp.cluster_utils.display_secrets_info"

.PHONY: load-k8s-secrets
load-k8s-secrets: ## Load secrets into Kubernetes backend
	ansible-playbook -e pattern_name="$(NAME)" -e pattern_dir="$(PATTERN_DIR)" $(EXTRA_PLAYBOOK_OPTS) "rhvp.cluster_utils.k8s_secrets"

.PHONY: load-secrets
load-secrets: ## Loads the secrets into the backend determined by values-global setting
	ansible-playbook -e pattern_name="$(NAME)" -e pattern_dir="$(PATTERN_DIR)" -e secrets_backing_store="$(SECRETS_BACKING_STORE)" $(EXTRA_PLAYBOOK_OPTS) "rhvp.cluster_utils.process_secrets"

.PHONY: legacy-load-secrets
legacy-load-secrets: ## Loads the secrets into vault (only)
	ansible-playbook -t "push_secrets" -e pattern_name="$(NAME)" -e pattern_dir="$(PATTERN_DIR)" $(EXTRA_PLAYBOOK_OPTS) "rhvp.cluster_utils.vault"

.PHONY: secrets-backend-vault
secrets-backend-vault: ## Edits values files to use default Vault+ESO secrets config
	yq -i '.global.secretStore.backend = "vault"' values-global.yaml
	MAIN_CLUSTERGROUP=$(yq '.main.clusterGroupName' values-global.yaml)
	MAIN_CLUSTERGROUP_FILE=values-$MAIN_CLUSTERGROUP.yaml
	@yq -i 'del(.clusterGroup.namespaces[] | select(. == "validated-patterns-secrets"))' "$MAIN_CLUSTERGROUP_FILE"
	@RES=$(yq '.clusterGroup.applications[] | select(.chart == "hashicorp-vault")' "$MAIN_CLUSTERGROUP_FILE" 2>/dev/null)
	if [ -z "$RES" ]; then
		echo "Adding vault application"
		yq -i '.clusterGroup.applications.vault = {"name": "vault", "namespace": "vault", "project": "'$MAIN_CLUSTERGROUP'", "chart": "hashicorp-vault", "chartVersion": "0.1.*"}' "$MAIN_CLUSTERGROUP_FILE"
	fi
	@RES=$(yq '.clusterGroup.namespaces[] | select(. == "vault")' "$MAIN_CLUSTERGROUP_FILE" 2>/dev/null)
	if [ -z "$RES" ]; then
		echo "Adding vault namespace"
		yq -i '.clusterGroup.namespaces += ["vault"]' "$MAIN_CLUSTERGROUP_FILE"
	fi
	@RES=$(yq '.clusterGroup.applications[] | select(.chart == "golang-external-secrets")' "$MAIN_CLUSTERGROUP_FILE" 2>/dev/null)
	if [ -z "$RES" ]; then
		echo "Adding golang-external-secrets application"
		yq -i '.clusterGroup.applications."golang-external-secrets" = {"name": "golang-external-secrets", "namespace": "golang-external-secrets", "project": "'$MAIN_CLUSTERGROUP'", "chart": "golang-external-secrets", "chartVersion": "0.1.*"}' "$MAIN_CLUSTERGROUP_FILE"
	fi
	@RES=$(yq '.clusterGroup.namespaces[] | select(. == "golang-external-secrets")' "$MAIN_CLUSTERGROUP_FILE" 2>/dev/null)
	if [ -z "$RES" ]; then
		echo "Adding golang-external-secrets namespace"
		yq -i '.clusterGroup.namespaces += ["golang-external-secrets"]' "$MAIN_CLUSTERGROUP_FILE"
	fi
	@git diff --exit-code || echo "Secrets backend set to vault, please review changes, commit, and push to activate in the pattern"

.PHONY: secrets-backend-kubernetes
secrets-backend-kubernetes: ## Edits values file to use Kubernetes+ESO secrets config
	yq -i '.global.secretStore.backend = "kubernetes"' values-global.yaml
	MAIN_CLUSTERGROUP=$(yq '.main.clusterGroupName' values-global.yaml)
	MAIN_CLUSTERGROUP_FILE=values-$MAIN_CLUSTERGROUP.yaml
	@RES=$(yq '.clusterGroup.namespaces[] | select(. == "validated-patterns-secrets")' "$MAIN_CLUSTERGROUP_FILE" 2>/dev/null)
	if [ -z "$RES" ]; then
		echo "Adding validated-patterns-secrets namespace"
		yq -i '.clusterGroup.namespaces += ["validated-patterns-secrets"]' "$MAIN_CLUSTERGROUP_FILE"
	fi
	@echo "Removing vault application"
	@yq -i 'del(.clusterGroup.applications[] | select(.chart == "hashicorp-vault"))' "$MAIN_CLUSTERGROUP_FILE"
	@echo "Removing vault namespace"
	@yq -i 'del(.clusterGroup.namespaces[] | select(. == "vault"))' "$MAIN_CLUSTERGROUP_FILE"
	@RES=$(yq '.clusterGroup.applications[] | select(.chart == "golang-external-secrets")' "$MAIN_CLUSTERGROUP_FILE" 2>/dev/null)
	if [ -z "$RES" ]; then
		echo "Adding golang-external-secrets application"
		yq -i '.clusterGroup.applications."golang-external-secrets" = {"name": "golang-external-secrets", "namespace": "golang-external-secrets", "project": "'$MAIN_CLUSTERGROUP'", "chart": "golang-external-secrets", "chartVersion": "0.1.*"}' "$MAIN_CLUSTERGROUP_FILE"
	fi
	@RES=$(yq '.clusterGroup.namespaces[] | select(. == "golang-external-secrets")' "$MAIN_CLUSTERGROUP_FILE" 2>/dev/null)
	if [ -z "$RES" ]; then
		echo "Adding golang-external-secrets namespace"
		yq -i '.clusterGroup.namespaces += ["golang-external-secrets"]' "$MAIN_CLUSTERGROUP_FILE"
	fi
	@git diff --exit-code || echo "Secrets backend set to kubernetes, please review changes, commit, and push to activate in the pattern"

.PHONY: secrets-backend-none
secrets-backend-none: ## Edits values files to remove secrets manager + ESO
	yq -i '.global.secretStore.backend = "none"' values-global.yaml
	MAIN_CLUSTERGROUP=$(yq '.main.clusterGroupName' values-global.yaml)
	MAIN_CLUSTERGROUP_FILE=values-$MAIN_CLUSTERGROUP.yaml
	@echo "Removing vault application"
	@yq -i 'del(.clusterGroup.applications[] | select(.chart == "hashicorp-vault"))' "$MAIN_CLUSTERGROUP_FILE"
	@echo "Removing golang-external-secrets application"
	@yq -i 'del(.clusterGroup.applications[] | select(.chart == "golang-external-secrets"))' "$MAIN_CLUSTERGROUP_FILE"
	@echo "Removing validated-patterns-secrets namespace"
	@yq -i 'del(.clusterGroup.namespaces[] | select(. == "validated-patterns-secrets"))' "$MAIN_CLUSTERGROUP_FILE"
	@echo "Removing vault namespace"
	@yq -i 'del(.clusterGroup.namespaces[] | select(. == "vault"))' "$MAIN_CLUSTERGROUP_FILE"
	@echo "Removing golang-external-secrets namespace"
	@yq -i 'del(.clusterGroup.namespaces[] | select(. == "golang-external-secrets"))' "$MAIN_CLUSTERGROUP_FILE"
	@git diff --exit-code || echo "Secrets backend set to none, please review changes, commit, and push to activate in the pattern"


##@ Validation Tasks

# We only check the remote ssh git branch's existance if we're not running inside a container
# as getting ssh auth working inside a container seems a bit brittle
# If the main repoUpstreamURL field is set, then we need to check against
# that and not target_repo
.PHONY: validate-origin
validate-origin: ## Verify the git origin is available
	@echo "Checking repository:"
	UPSTREAMURL=$$(yq -r '.main.git.repoUpstreamURL // (.main.git.repoUpstreamURL = "")' values-global.yaml)
	if [ -z "$$UPSTREAMURL" ]; then
		echo -n "  $(TARGET_REPO) - branch '$(TARGET_BRANCH)': "
		git ls-remote --exit-code --heads $(TARGET_REPO) $(TARGET_BRANCH) >/dev/null && echo "OK" || (echo "NOT FOUND"; exit 1)
	else
		echo "Upstream URL set to: $$UPSTREAMURL"
		echo -n "  $$UPSTREAMURL - branch '$(TARGET_BRANCH)': "
		git ls-remote --exit-code --heads $$UPSTREAMURL $(TARGET_BRANCH) >/dev/null && echo "OK" || (echo "NOT FOUND"; exit 1)
	fi

.PHONY: validate-cluster
validate-cluster: ## Do some cluster validations before installing
	@echo "Checking cluster:"
	@echo -n "  cluster-info: "
	@oc cluster-info >/dev/null && echo "OK" || (echo "Error"; exit 1)
	@echo -n "  storageclass: "
	@if [ $(oc get storageclass -o go-template='{{printf "%d\n" (len .items)}}') -eq 0 ]; then
		echo "WARNING: No storageclass found"
	else
		echo "OK"
	fi


.PHONY: validate-schema
validate-schema: ## Validates values files against schema in common/clustergroup
	VAL_PARAMS=$(for i in ./values-*.yaml; do echo -n "$${i} "; done)
	@echo -n "Validating clustergroup schema of: "
	@set -e
	for i in $VAL_PARAMS; do
		echo -n " $i"
		helm template oci://quay.io/hybridcloudpatterns/clustergroup $(HELM_OPTS) -f "$i" >/dev/null
	done
	@echo

.PHONY: validate-prereq
validate-prereq: ## Verify pre-requisites
	GLOBAL_PATTERN=$(yq -r .global.pattern values-global.yaml)
	@if [ $(NAME) != $GLOBAL_PATTERN ]; then
		echo ""
		echo "WARNING: folder directory is \"$(NAME)\" and global.pattern is set to \"$GLOBAL_PATTERN\""
		echo "this can create problems. Please make sure they are the same!"
		echo ""
	fi
	@if [ ! -f /run/.containerenv ]; then
		echo "Checking prerequisites:"
		echo -n "  Check for python-kubernetes: "
		if ! ansible -m ansible.builtin.command -a "{{ ansible_python_interpreter }} -c 'import kubernetes'" localhost > /dev/null 2>&1; then echo "Not found"; exit 1; fi
		echo "OK"
		echo -n "  Check for kubernetes.core collection: "
		if ! ansible-galaxy collection list | grep kubernetes.core > /dev/null 2>&1; then echo "Not found"; exit 1; fi
		echo "OK"
	else
		if [ -f values-global.yaml ]; then
			OUT=$(yq -r '.main.multiSourceConfig.enabled // (.main.multiSourceConfig.enabled = "false")' values-global.yaml)
			if [ "${OUT,,}" = "false" ]; then
				echo "You must set \".main.multiSourceConfig.enabled: true\" in your 'values-global.yaml' file"
				echo "because your common subfolder is the slimmed down version with no helm charts in it"
				exit 1
			fi
		fi
	fi

.PHONY: argo-healthcheck
argo-healthcheck: ## Checks if all argo applications are synced
	@echo "Checking argo applications"
	APPS=$(oc get applications.argoproj.io -A -o jsonpath='{range .items[*]}{@.metadata.namespace}{","}{@.metadata.name}{"\n"}{end}')
	@NOTOK=0
	for i in $APPS; do
		n=$(echo "$i" | cut -f1 -d,)
		a=$(echo "$i" | cut -f2 -d,)
		STATUS=$(oc get -n "$n" applications.argoproj.io/"$a" -o jsonpath='{.status.sync.status}')
		if [[ $STATUS != "Synced" ]]; then
			NOTOK=$(( $NOTOK + 1))
		fi
		HEALTH=$(oc get -n "$n" applications.argoproj.io/"$a" -o jsonpath='{.status.health.status}')
		if [[ $HEALTH != "Healthy" ]]; then
			NOTOK=$(( $NOTOK + 1))
		fi
		echo "$n $a -> Sync: $STATUS - Health: $HEALTH"
	done
	if [ $NOTOK -gt 0 ]; then
	    echo "Some applications are not synced or are unhealthy"
	    exit 1
	fi


##@ Testing and CI Tasks

.PHONY: load-iib
load-iib: ## CI target to install Index Image Bundles
	@set -e
	if [ x$(INDEX_IMAGES) != x ]; then
		ansible-playbook $(EXTRA_PLAYBOOK_OPTS) rhvp.cluster_utils.iib_ci
	else
		echo "No INDEX_IMAGES defined. Bailing out"
		exit 1
	fi

.PHONY: qe-tests
qe-tests: ## Runs the tests that QE runs
	@set -e
	if [ -f ./tests/interop/run_tests.sh ]; then
		pushd ./tests/interop
		./run_tests.sh
		popd
	else
		echo "No ./tests/interop/run_tests.sh found skipping"
	fi

.PHONY: super-linter
super-linter: ## Runs super linter locally
	rm -rf .mypy_cache
	podman run -e RUN_LOCAL=true -e USE_FIND_ALGORITHM=true \
					-e VALIDATE_ANSIBLE=false \
					-e VALIDATE_BASH=false \
					-e VALIDATE_CHECKOV=false \
					-e VALIDATE_DOCKERFILE_HADOLINT=false \
					-e VALIDATE_JSCPD=false \
					-e VALIDATE_JSON_PRETTIER=false \
					-e VALIDATE_MARKDOWN_PRETTIER=false \
					-e VALIDATE_KUBERNETES_KUBECONFORM=false \
					-e VALIDATE_PYTHON_PYLINT=false \
					-e VALIDATE_SHELL_SHFMT=false \
					-e VALIDATE_TEKTON=false \
					-e VALIDATE_YAML=false \
					-e VALIDATE_YAML_PRETTIER=false \
					$(DISABLE_LINTERS) \
					-v $(PWD):/tmp/lint:rw,z \
					-w /tmp/lint \
					ghcr.io/super-linter/super-linter:slim-v7

.PHONY: test
test: ## Run schema validation tests using PATTERN_OPTS
	MAIN_CLUSTERGROUP=$(yq '.main.clusterGroupName' values-global.yaml)
	MAIN_CLUSTERGROUP_FILE=values-$MAIN_CLUSTERGROUP.yaml
	PATTERN_OPTS=${PATTERN_OPTS:--f values-global.yaml -f $MAIN_CLUSTERGROUP_FILE}
	@echo -n "Validating clustergroup schema with pattern options: "
	@set -e; helm template oci://quay.io/hybridcloudpatterns/clustergroup $(HELM_OPTS) $PATTERN_OPTS >/dev/null
	@echo "OK"

.PHONY: deploy upgrade legacy-deploy legacy-upgrade
deploy upgrade legacy-deploy legacy-upgrade:
	@echo "UNSUPPORTED TARGET: please switch to 'operator-deploy'"; exit 1
