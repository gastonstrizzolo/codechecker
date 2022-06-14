
const state = {
  cleanupPlans: []
};
const mutations = {
  setCleanupPlans(state, cleanUpPlans) {
    state.cleanupPlans = cleanUpPlans;
  }
};
const getters = {
  getIdCleanup: state => id => {
    const result = state.cleanupPlans.find(plan => plan.id === id);
    return result.id_db;
  }
};

export default {
  namespaced: true,
  state,
  getters,
  mutations
};
