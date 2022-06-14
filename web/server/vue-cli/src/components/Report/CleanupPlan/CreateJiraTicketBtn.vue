<template>
  <v-btn
    color="primary"
    class="set-cleanup-plan-btn mr-5"
    outlined
    small
    :disabled="$route.query['cleanup-plan'] === undefined || (project === '' || project === null)"
    :loading="isLoading"
    @click="createJiraTicket"
  >
    <v-icon class="mr-1" small>
      mdi-jira
    </v-icon>
    Create jira ticket
  </v-btn>
</template>

<script>

import { handleThriftError, jiraService  } from "@cc-api";
import { mapGetters } from "vuex";
export default {
  name: "CreateJiraTicketBtn",
  props: {
    project: { type: String, default: "" }
  },
  data() {
    return {
      isLoading: false
    };
  },
  computed: {
    ...mapGetters({
      getIdCleanupPlan: "cleanupPlans/getIdCleanup"
    })
  },
  methods: {

    createJiraTicket() {
      const cleanupPlanQuery = this.$route.query["cleanup-plan"];
      if (cleanupPlanQuery === undefined) return;

      this.isLoading = true;
      const fullUrl = this.$route.fullPath;
      const cleanupPlanArray = Array.isArray(cleanupPlanQuery) ? cleanupPlanQuery : [ cleanupPlanQuery ];

      cleanupPlanArray.forEach(cleanupPlan => {
        const idCleanupPlan = this.getIdCleanupPlan(cleanupPlan);

        new Promise(resolve => {
          jiraService.getClient().createJiraTicket(+idCleanupPlan, fullUrl, this.project, cleanupPlan, handleThriftError(response => {
            this.isLoading = false;
            resolve(response.forEach(tag => {
              this.$emit("alertData", { isError: tag.isError, msg: tag.msg, link: tag.link });
            }));
          }));
        });
      });
    }
  }
};
</script>

<style scoped>

</style>
